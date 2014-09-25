package com.spvwallet

import scala.annotation.tailrec
import akka.util.ByteString
import java.util.Arrays
import java.net.{InetSocketAddress, InetAddress}
import java.security.SecureRandom
import java.nio.{ByteBuffer, ByteOrder}
import org.bouncycastle.util.encoders.Hex
import org.apache.commons.lang3.ArrayUtils
import org.joda.time.DateTime
import CryptoUtils._
import org.bouncycastle.math.ec.ECPoint
import java.io.ByteArrayOutputStream
import scala.util.{Try, Success, Failure}

case class Address(p: ECPoint, addr: String, account: Int)

/**
 * Produces a (infinite) series of addresses lazily
 */
trait DeterministicWallet {
  val pub: Stream[Address]
}

/**
 * Electrum style deterministic wallet
 */
class Electrum(secret: Option[Array[Byte]], mpub: Array[Byte]) extends DeterministicWallet {
  import CryptoUtils._
  val mpubHex = Hex.toHexString(mpub)
  val x: Array[Byte] = new Array(32)
  val y: Array[Byte] = new Array(32)
  Array.copy(mpub, 0, x, 0, 32)
  Array.copy(mpub, 32, y, 0, 32)
  val mPubPoint = ecSpec.getCurve().createPoint(BigInt(1, x).bigInteger, BigInt(1, y).bigInteger)
  
  // Calculate the multiplicative factor
  private def deriveExp(group: Int, i: Int): BigInt = {
    val bb = ByteBuffer.allocate(100)
    bb.put(s"$i:$group:".getBytes())
    bb.put(mpub)
    bb.flip()
    val sequence = ArrayUtils.subarray(bb.array, 0, bb.limit)
    BigInt(1, CryptoUtils.dhash(sequence))
  }
  
  // Derive a public key address
  def derivePub(group: Int, i: Int): Address = {
    val d = deriveExp(group, i)
    val pub = mPubPoint.add(ecSpec.getG().multiply(d.bigInteger)).normalize()
    Address(pub, pubToAddress(pub), group)
  }

  // Interleave normal and change addresses into a single stream
  val interleaved = Stream.from(0).map(i => derivePub(0, i)).zip(Stream.from(0).map(i => derivePub(1, i)))
  val pub = interleaved.flatMap { case (a, b) => Seq(a, b) }
}

/**
 * Output script type
 */
trait ScriptPub {
  /**
   * Where the coins went
   */
  def toAddress(): String
}

/**
 * The standard pay to hash script type
 */
sealed class Pay2Hash(pubKeyHash: Array[Byte]) extends ScriptPub {
  def toAddress() = CryptoUtils.pubHashToAddress(pubKeyHash)
} 

/**
 * Any script we don't know
 * 
 * For the moment, only pay 2 hash scripts are supported
 */
object UnknownScript extends ScriptPub {
  def toAddress() = ""
}

class Script(codes: Array[Byte]) {
  import Script._
  private def readNextOpCode(bb: ByteBuffer, data: ByteArrayOutputStream): Try[Int] = {
    /* Skip some bytes and put them aside
     * 
     * Used to store the data vs the opcodes
     */
    def skip(cSkip: Int) = {
      val bytes: Array[Byte] = new Array(cSkip)
      bb.get(bytes)
      data.write(bytes)
    }
    
    if (bb.hasRemaining) {
      // Different types of PUSH_DATA opcodes
      val op: Int = bb.get() & 0xFF
      if (op <= 75) skip(op)
      else op match {
        case 76 => 
          val len = bb.get()
          skip(len)
        case 77 =>
          val len = bb.getShort()
          skip(len)
        case 78 =>
          val len = bb.getInt()
          skip(len)
        case _ =>
      }
      
      Success(op)
    } else Failure(null)
  }
  
  /** Get the opcodes so that we can match we known versions */
  private def extractOpCodes(): (List[Int], Array[Byte]) = {
    val bb = ByteBuffer.wrap(codes)
    val data = new ByteArrayOutputStream(codes.length)
    val opCodes = Iterator.continually(readNextOpCode(bb, data)).takeWhile(_.isSuccess).map(_.get).toList
    (opCodes, data.toByteArray())
  }
  
  /** Convert to one of the standard transaction types */
  def toStandardTransaction(): ScriptPub = {
    val (opCodes, data) = extractOpCodes()
    opCodes match {
      case List(OP_DUP, OP_HASH160, OP_DATA_20, OP_EQUALVERIFY, OP_CHECKSIG) => new Pay2Hash(data)
      case _ => UnknownScript
    }
  }
}
object Script {
  val OP_DUP = 118
  val OP_HASH160 = 169
  val OP_DATA_20 = 20
  val OP_EQUALVERIFY = 136
  val OP_CHECKSIG = 172
  val OP_DATA_65 = 65
  val OP_EQUAL = 135
  val OP_DATA_33 = 33
}
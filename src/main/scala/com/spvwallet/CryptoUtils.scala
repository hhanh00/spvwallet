package com.spvwallet

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.crypto.digests.{RIPEMD160Digest, SHA256Digest, SHA512Digest}
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.{KeyParameter, ECDomainParameters}
import org.apache.commons.lang3.StringUtils
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.encoders.Hex
import org.apache.commons.lang3.ArrayUtils
import scala.util._
import java.util.Arrays
import akka.util.ByteString

/** 
 *  Base 58 encoding/decoding
 */
object Base58 {
  private val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  val base = 58
  /**
   * Leading zero bytes are first put aside
   * Then we do a standard mathematical conversion to base 58 using the alphabet above
   * Finally, we replace the zero bytes with '1' which are the 0 in base 58
   * Note: Without the first and third steps leading zeroes would be dropped off during roundtripping
   */
  def encode(input: Array[Byte]): String = {
    val leadingZerosTo1 = input.takeWhile(_ == 0).map(_ => "1").mkString // convert leading zero-bytes to '1's
    val os = new StringBuffer()
    val x = Iterator.iterate(BigInt(1, input)) { i: BigInt => // repeatedly pick the remainder and divider mod 58 
      val d = alphabet((i % 58).toInt) // replace with letter from alphabet
      os.append(d)
      i / 58
      }.takeWhile(_ > 0) // continue until we reach 0 - .length
      .length // forces evaluation
    leadingZerosTo1 + os.toString.reverse // step 3
  } 
  
  /**
   * Reverse the steps of the encoding
   * Leading '1' are put aside
   * Do a conversion base to base 10
   * Add leading zeroes
   */
  def decode(input: String): Array[Byte] = {
    val (leading, payload) = input.span(_ == '1') // split the leading '1's and the rest into two parts
    val b = payload.foldLeft(BigInt(0))((acc, digit) => (acc * 58 + alphabet.indexOf(digit))) // convert to base 10
    val decodePayload = CryptoUtils.toUnsignedArray(b.bigInteger) // extract to byte array - becareful of not using BigInteger.toByteArray!
    val leadingZeros: Array[Byte] = new Array(leading.length) // prepare leading zeros
    Arrays.fill(leadingZeros, 0.toByte)
    ArrayUtils.addAll(leadingZeros, decodePayload:_*) // concatenate them together
  }
}

object CryptoUtils {
  type Hash = Array[Byte]
  val genesisHash = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"
  
  Security.addProvider(new BouncyCastleProvider())
  val f = KeyFactory.getInstance("ECDSA", "BC");
  val ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
  val ecDomain = new ECDomainParameters(ecSpec.getCurve, ecSpec.getG, ecSpec.getN)
  val hmac = new HMac(new SHA512Digest())

  /**
   * Flip a hex string
   * 
   *  Hashes are stored in little endian but displayed in big endian. Reverse a hex string
   *  Not very fast but only used for debugging
   */
  def reverseHexString(hs: String) = Hex.toHexString((Vector() ++ Hex.decode(hs)).reverse.toArray[Byte])
  
  def readVarInt(bb: ByteBuffer): Int = readVarLong(bb).toInt
  def readVarLong(bb: ByteBuffer): Long = {
    val b = bb.get() & 0xFF
    b match {
      case 0xFD => bb.getShort() & 0xFFFFL
      case 0xFE => bb.getInt() & 0xFFFFFFFFL
      case 0xFF => bb.getLong()
      case _ => b & 0xFFL
    }
  }
  def writeVarInt(bb: ByteBuffer, v: Int) = writeVarLong(bb, v.toLong)
  def writeVarLong(bb: ByteBuffer, v: Long) = {
    if (v > Int.MaxValue) {
      bb.put(0xFF.toByte)
      bb.putLong(v)
    }
    else if (v > Short.MaxValue) {
      bb.put(0xFE.toByte)
      bb.putInt(v.toInt)
    }
    else if (v >= 0xFD) {
      bb.put(0xFD.toByte)
      bb.putShort(v.toShort)
    }
    else
      bb.put(v.toByte)
  } 
  
  def readHash(bb: ByteBuffer) = {
    val hash: Array[Byte] = new Array(32)
    bb.get(hash)
    hash
  }
  
  /**
   * Converts a bigint into its byte representation
   * 
   * Java toByteArray puts an undesirable leading 0 byte to preserve the sign
   */
  def toUnsignedArray(b: BigInteger) = {
    val x = b.toByteArray()
    if (x(0) == 0) 
      ArrayUtils.subarray(x, 1, x.length)
    else
      x
  }
  
  /**
   * Calculate the checksum in B58Check
   */
  private def calcChecksum(input: Array[Byte]) = {
    val res = new Array[Byte](32)
    val sha256 = new SHA256Digest()
    sha256.update(input, 0, input.length)
    sha256.doFinal(res, 0)
    sha256.update(res, 0, res.length)
    sha256.doFinal(res, 0)
    ArrayUtils.subarray(res, 0, 4)
  }
  
  /**
   * Add the checksum
   */
  private def addChecksum(input: Array[Byte]): Array[Byte] = {
    val checksum = calcChecksum(input)
    val b: Array[Byte] = new Array(input.length + 4)
    
    Array.copy(input, 0, b, 0, input.length)
    Array.copy(checksum, 0, b, input.length, 4)
    b
  }
  

  def B58Check(input: Array[Byte]): String = Base58.encode(addChecksum(input))
  
  def pubToAddress(q: ECPoint): String = pubHashToAddress(pubToHash(q))
  def pubHashToAddress(hash: Array[Byte]): String = {
    val b: Array[Byte] = new Array(hash.length + 1)
    b(0) = BitcoinMessage.addressVersion 
    Array.copy(hash, 0, b, 1, hash.length)
    Base58.encode(addChecksum(b))
  }
  def pubToHash(q: ECPoint) = {
    val ba = pubToKey(q, false)
    hash160(ba)
  }
  def hash160(input: Array[Byte]): Hash = {
    val sha256 = new SHA256Digest()
    sha256.update(input, 0, input.length)
    val shaResult = new Array[Byte](32)
    sha256.doFinal(shaResult, 0)
    val ripe160 = new RIPEMD160Digest()
    ripe160.update(shaResult, 0, shaResult.length)
    val ripeResult = new Array[Byte](20)
    ripe160.doFinal(ripeResult, 0)
    ripeResult
  }
  
  def pubToKey(point: ECPoint, compressed: Boolean) = {
    val bb = ByteBuffer.allocate(if (compressed) 33 else 65)
    if (compressed) {
      /* In compressed form, put X and the parity of Y
       * The curve is symmetric along the X-axis
       */
      bb.put(point.getXCoord.getEncoded)
      bb.put((if (point.getYCoord.testBitZero()) 0x03 else 0x02).toByte) // 3 if odd, 2 if even
    }
    else {
      bb.put(0x04.toByte)
      bb.put(point.getXCoord.getEncoded)
      bb.put(point.getYCoord.getEncoded)
    }
    bb.array
  }
  
  def sha(v: Array[Byte]): Array[Byte] = {
    val dh: Array[Byte] = new Array(32)
    val sha256 = new SHA256Digest()
    sha256.update(v, 0, v.length)
    sha256.doFinal(dh, 0)
    dh
  }
  def dhash(v: Array[Byte]) = {
    val dh = sha(v)
    val sha256 = new SHA256Digest()
    sha256.update(dh, 0, dh.length)
    sha256.doFinal(dh, 0)
    dh
  }
  
  def combineHashes(l: Hash, r: Hash): Hash = {
    val bb = ByteBuffer.allocate(l.length + r.length)
    bb.put(l)
    bb.put(r)
    dhash(bb.array)
  }
  def compareHashes(l: Hash, r: Hash): Boolean = {
    val lh: Seq[Byte] = l
    val rh: Seq[Byte] = r
    lh == rh
  }
  def computeHash(headerBB: ByteBuffer): Hash = {
      val bytes: Array[Byte] = new Array(headerBB.limit)
      headerBB.get(bytes)
      dhash(bytes)
  }
}
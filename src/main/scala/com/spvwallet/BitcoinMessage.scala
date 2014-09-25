package com.spvwallet

import akka.util.ByteString
import java.util.Arrays
import java.net.{InetSocketAddress, InetAddress}
import java.security.SecureRandom
import java.nio.{ByteBuffer, ByteOrder}
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.crypto.digests.SHA256Digest
import org.apache.commons.lang3.ArrayUtils
import org.joda.time.DateTime
import CryptoUtils._
import scala.annotation.tailrec
import org.bouncycastle.math.ec.ECPoint
import scala.util.hashing.MurmurHash3

class BloomFilter(N: Int, P: Double, cHashes: Int, nTweak: Int) {
  // Recommended size based on a number of elements and the probability of collision
  val sz = Math.min((-1 / Math.pow(Math.log(2), 2) * N * Math.log(P)) / 8, 36000).toInt
  val size = ((sz-1) / 8 + 1) * 8 // Round up to a multiple of the size of long
  val bitSize = 8 * size
  val buckets: scala.collection.mutable.BitSet = new scala.collection.mutable.BitSet(bitSize)
  val seeds = (for(i <- 0 until cHashes) yield i * 0xFBA4C795 + nTweak).toList
  
  private def addHash(h: Hash) = {
    for (seed <- seeds) {
      val hh = MurmurHash3.bytesHash(h, seed)
      val p = ((hh.toLong & 0xFFFFFFFFL) % bitSize).toInt // Because java has no unsigned int
      buckets(p) = true
    }
  }
  def setToMost() = {
    for (i <- 1 until bitSize) 
      buckets += i
  }
  def setToHalf() = {
    for (i <- 0 until bitSize) 
      if (i % 2 == 0)
        buckets += i
  }
  def setToFew() = {
    buckets += 5
  }
  
  def addKey(pubKey: ECPoint) = {
    val serKey = pubToKey(pubKey, false)
    addHash(serKey)
    val hash = hash160(serKey) 
    addHash(hash)
    toFilterLoad()
  }
  
  def toFilterLoad() = {
    // Copy the content of the filter as a bitmask in LE
    val filter: Array[Byte] = new Array(size)
    val bb = ByteBuffer.wrap(filter)
    bb.order(ByteOrder.LITTLE_ENDIAN)
    val bmask = buckets.toBitMask
    for (b <- bmask)
      bb.putLong(b)
    FilterLoad(filter, cHashes, nTweak)
  }
}
object BloomFilter {
  def apply() = {
    val r = new SecureRandom()
    new BloomFilter(10, 0.0001, 4, r.nextInt())
  }
}

trait BitcoinMessage {
  def toByteString() = ByteString()
}
sealed case class Version(height: Int, local: InetSocketAddress, remote: InetSocketAddress) extends BitcoinMessage {
  override def toByteString() = {
    BitcoinMessage.wrapPayload("version") { payload =>
      payload.order(ByteOrder.LITTLE_ENDIAN)
      payload.putInt(BitcoinMessage.version)
      payload.putLong(1) // NODE_NETWORK
      payload.putLong(BitcoinMessage.currentTime)
      payload.put(BitcoinMessage.networkAddress(false, remote))
      payload.put(BitcoinMessage.networkAddress(false, new InetSocketAddress("192.168.0.100", 7333)))
      val random = new SecureRandom()
      payload.putLong(random.nextLong())
      BitcoinMessage.putString(payload, "/Satoshi:0.9.2.1/")
      payload.putInt(height)
      payload.put(1.toByte)
    }
  }
}
object Version {
  def apply(payload: Array[Byte]) = {
    val bb = ByteBuffer.wrap(payload)
    bb.order(ByteOrder.LITTLE_ENDIAN)
    val version = bb.getInt()
    bb.getLong()
    val ts = bb.getLong()
    val local = BitcoinMessage.getNetworkAddress(bb, false)
    val remote = BitcoinMessage.getNetworkAddress(bb, false)
    val nonce = bb.getLong()
    BitcoinMessage.getString(bb)
    val height = bb.getInt()
    new Version(height, local.address, remote.address)
  }
}

sealed case class Verack() extends BitcoinMessage {
  override def toByteString() = {
    BitcoinMessage.wrapPayload("verack") { payload => }
  }
}

sealed case class GetAddr() extends BitcoinMessage {
  override def toByteString() = {
    BitcoinMessage.wrapPayload("getaddr") { payload => }
  }
}

case class AddrRec(ts: Int, address: InetSocketAddress)
sealed case class Addr(addrs: List[AddrRec]) extends BitcoinMessage
object Addr {
  def apply(payload: Array[Byte]) = {
    val bb = ByteBuffer.wrap(payload)
    bb.order(ByteOrder.LITTLE_ENDIAN)
    val count = readVarInt(bb)
    new Addr((for (i <- 0 until count) yield {
      val net = BitcoinMessage.getNetworkAddress(bb, true)
      net
    }).toList)
  }
}

case class Inv(tpe: Int, hash: Hash) {
  override def toString() = reverseHexString(Hex.toHexString(hash))
}
object Inv {
  def apply(bb: ByteBuffer) = {
    val tpe = bb.getInt()
    val hash = BitcoinMessage.allocateHashBytes()
    bb.get(hash)
    val inv = new Inv(tpe, hash)
    inv
  }
}
sealed case class InvVector(invs: List[Inv]) extends BitcoinMessage
object InvVector {
  def apply(payload: Array[Byte]) = {
    val bb = ByteBuffer.wrap(payload)
    bb.order(ByteOrder.LITTLE_ENDIAN)
    val count = readVarInt(bb)
    new InvVector((for (i <- 0 until count) yield Inv(bb)).toList)
  }
}

sealed case class GetData(invs: List[Inv]) extends BitcoinMessage {
  override def toByteString() = {
    BitcoinMessage.wrapPayload("getdata") { payload => 
      writeVarInt(payload, invs.length)
      for (inv <- invs) {
        payload.putInt(inv.tpe)
        payload.put(inv.hash)
      }
    }
  }
}

sealed case class Mempool() extends BitcoinMessage {
  override def toByteString() = {
    BitcoinMessage.wrapPayload("mempool") { payload => 
    }
  }
}

case class Headers(headers: List[Header]) extends BitcoinMessage
sealed case class GetHeaders(hashes: List[String], hashStop: String) extends BitcoinMessage {
  override def toByteString() = {
    BitcoinMessage.wrapPayload("getheaders") { payload => 
      payload.putInt(BitcoinMessage.version)
      writeVarInt(payload, hashes.length)
      for (h <- hashes) {
        payload.put(Hex.decode(h))
      }
      payload.put(Hex.decode(hashStop))
    }
  }
}
case class Header(hash: Hash, version: Int, prevBlockHash: Hash, merkleRoot: Hash, ts: Int, bits: Int, nonce: Int) {
  def writePayload(bb: ByteBuffer) = {
    bb.putInt(version)
    bb.put(prevBlockHash)
    bb.put(merkleRoot)
    bb.putInt(ts)
    bb.putInt(bits)
    bb.putInt(nonce)
  }
  override def toString() = reverseHexString(Hex.toHexString(hash))
}
object Headers {
  val headerSize = 80
  def apply(payload: Array[Byte]) = {
    val bb = ByteBuffer.wrap(payload)
    bb.order(ByteOrder.LITTLE_ENDIAN)
    val count = readVarInt(bb)
    val headerList = (for (i <- 0 until count) yield {
      val hash = computeHeaderHash(bb.slice())
      val version = bb.getInt()
      val prevBlock = BitcoinMessage.allocateHashBytes()
      bb.get(prevBlock)
      val merkleRoot = BitcoinMessage.allocateHashBytes()
      bb.get(merkleRoot)
      val ts = bb.getInt()
      val bits = bb.getInt()
      val nonce = bb.getInt()
      val txCount = readVarInt(bb)
      Header(hash, version, prevBlock, merkleRoot, ts, bits, nonce)
    }).toList
    new Headers(headerList)
  }
  def computeHeaderHash(headerBB: ByteBuffer): Hash = {
      val headerBytes: Array[Byte] = new Array(Headers.headerSize)
      headerBB.get(headerBytes)
      dhash(headerBytes)
  }
}

sealed case class MerkleBlock(header: Header, txCount: Int, merkleTree: List[String], flags: Array[Byte], txHashes: List[String]) extends BitcoinMessage
object MerkleBlock {
  def apply(payload: Array[Byte]) = {
    val bb = ByteBuffer.wrap(payload)
    bb.order(ByteOrder.LITTLE_ENDIAN)
    val hash = Headers.computeHeaderHash(bb.slice())
    val version = bb.getInt()
    val prevBlock = BitcoinMessage.allocateHashBytes()
    bb.get(prevBlock)
    val merkleRoot = BitcoinMessage.allocateHashBytes()
    bb.get(merkleRoot)
    val ts = bb.getInt()
    val bits = bb.getInt()
    val nonce = bb.getInt()
    val txCount = bb.getInt()
    val hashesCount = readVarInt(bb)
    val merkleTree = (for (i <- 0 until hashesCount) yield {
      val hash = BitcoinMessage.allocateHashBytes()
      bb.get(hash)
      Hex.toHexString(hash) 
    }).toList
    val flagsCount = readVarInt(bb)
    val flags: Array[Byte] = new Array(flagsCount)
    bb.get(flags)
    val header = Header(hash, version, prevBlock, merkleRoot, ts, bits, nonce)
    
    def extractTxHashes(): List[Hash] = {
      // Copy the flags to a bitset
      val len = ((flags.length-1) / 8) + 1
      val bb = ByteBuffer.allocate(len * 8)
      bb.put(flags)
      bb.flip()
      bb.limit(bb.capacity)
      val bits: Array[Long] = new Array(len)
      bb.order(ByteOrder.LITTLE_ENDIAN)
      for (i <- 0 until len) {
        bits(i) = bb.getLong()
      }
      val bitset = scala.collection.immutable.BitSet.fromBitMask(bits.toArray)
        
      val powersOf2 = Stream.iterate(1)(_ * 2)
      val merkleHashes = merkleTree.map(Hex.decode(_))
      val n = txCount
      
      // Determine the height of the tree. It's the first power of 2 that exceeds the number of transactions
      val height = powersOf2.zipWithIndex.dropWhile { case (p, _) => p < n}.head._2
      
      // Compute the width of the tree on each level
      // We know the number of leaves and each level is half the next one (rounding up)
      val widths = Stream.iterate(n) { i =>
        if (i % 2 == 1)
          i / 2 + 1
        else
          i / 2
      }.take(height + 1).reverse.toVector // reverse because height = 0 is the root
  
      /***
       * bitindex: current index in the flag bitset
       * h: current height
       * index: current node position in the current level
       * merkleHashes: remaining list of merkle hashes
       *
       * This function has no side effect
       */
      def parse(bitIndex: Int, h: Int, index: Int, merkleHashes: List[Hash], txHashes: List[Hash]): (Hash, Int, List[Hash], List[Hash]) = {
        // Check the current bit to see if it is for a node that is a parent of a matching transaction
        val isParent = bitset(bitIndex)
        
        // We recurse if we are in the middle of the tree (not at a leaf) and the node is the parent of a matching node
        // The idea of the partial merkle tree is to ommit branches that do not include any matching transaction and replace them by their 
        // hashes
        if (h < height && isParent) {
          // Recurse the left branch
          val (leftHash, leftBitsUsed, m2, tx2) = parse(bitIndex + 1, h + 1, index * 2, merkleHashes, txHashes)
          // Recurse the right branch. By definition of the merkle tree, if the right branch does not exist, reuse the left branch hash
          val (rightHash, rightBitsUsed, m3, tx3) = if (index * 2 + 1 >= widths(h + 1))
            (leftHash, 0, m2, tx2)
          else
            parse(bitIndex + 1 + leftBitsUsed, h + 1, index * 2 + 1, m2, tx2)
          // Concatenate left and right hash and compute the hash of the result
          (combineHashes(leftHash, rightHash), leftBitsUsed + rightBitsUsed + 1, m3, tx3)
        }
        else
        {
          // No further traversal from this node. Take one hash from the merkle hash list instead
          (merkleHashes.head, 1, merkleHashes.tail, 
              if (h == height && isParent) 
                merkleHashes.head :: txHashes 
              else txHashes)
        }
      }
      val r = parse(0, 0, 0, merkleHashes, Nil)
      val computedMerkleRoot: Seq[Byte] = r._1
      val headerMerkleRoot: Seq[Byte] = header.merkleRoot
      
      if (computedMerkleRoot != headerMerkleRoot)
        throw new RuntimeException("Block does not match merkle root")
      r._4
    }
    
    val txHashes = extractTxHashes()
    val mb = new MerkleBlock(header, txCount, merkleTree, flags, txHashes.map(Hex.toHexString(_)))
    mb
  }
}

case class OutPoint(txHash: String, index: Int)
case class TxIn(outpoint: OutPoint, script: String, sequence: Int)
case class TxInX(in: TxIn, address: String)
case class TxOut(value: Long, script: String, address: String)
sealed case class Tx(hash: Hash, txIns: List[TxIn], txOuts: List[TxOut]) extends BitcoinMessage {
  override def toString() = reverseHexString(Hex.toHexString(hash))
}
object Tx {
  def readScript(bb: ByteBuffer) = {
    val scriptLen = CryptoUtils.readVarInt(bb)
    val script: Array[Byte] = new Array(scriptLen)
    bb.get(script)
    script
  }
  
  def apply(payload: Array[Byte]) = {
    BitcoinMessage.unwrapPayload(payload) { bb =>
      val txHash = CryptoUtils.computeHash(bb.slice())
      val version = bb.getInt()
      val cTxIn = readVarInt(bb)
      val txIns = (for (iTxIn <- 0 until cTxIn) yield {
        val txHash = readHash(bb)
        val index = bb.getInt()
        val prevOutput = OutPoint(Hex.toHexString(txHash), index)
        val script = readScript(bb)
        val sequence = bb.getInt()
        TxIn(prevOutput, Hex.toHexString(script), sequence)
      }).toList
      val cTxOut = CryptoUtils.readVarInt(bb)
      val txOuts = (for (iTxOut <- 0 until cTxOut) yield {
        val value = bb.getLong()
        val script = readScript(bb)
        val s = new Script(script)
        val address = s.toStandardTransaction().toAddress
        TxOut(value, Hex.toHexString(script), address)
      }).toList
      val lockTime = bb.getInt()
      new Tx(txHash, txIns, txOuts)
    }
  }
}

sealed case class Reject(msg: String, code: Byte, reason: String) extends BitcoinMessage
object Reject {
  def apply(payload: Array[Byte]) = {
    val bb = ByteBuffer.wrap(payload)
    bb.order(ByteOrder.LITTLE_ENDIAN)
    val msg = BitcoinMessage.getString(bb)
    val code = bb.get()
    val reason = BitcoinMessage.getString(bb)
    new Reject(msg, code, reason)
  }
}

sealed case class GetBlocks(hashes: List[String], hashStop: String) extends BitcoinMessage {
  override def toByteString() = {
    BitcoinMessage.wrapPayload("getblocks") { payload => 
      payload.putInt(BitcoinMessage.version)
      writeVarInt(payload, hashes.length)
      for (h <- hashes) {
        payload.put(Hex.decode(h))
      }
      payload.put(Hex.decode(hashStop))
    }
  }
}
sealed case class FilterLoad(filter: Array[Byte], cHash: Int, nTweak: Int) extends BitcoinMessage {
  override def toByteString() = {
    BitcoinMessage.wrapPayload("filterload") { payload =>
      writeVarInt(payload, filter.length)
      payload.put(filter)
      payload.putInt(cHash)
      payload.putInt(nTweak)
      payload.put(0.toByte)
    }
  }
}

sealed case class FilterAdd(data: Array[Byte]) extends BitcoinMessage {
  override def toByteString() = {
    BitcoinMessage.wrapPayload("filteradd") { payload =>
      writeVarInt(payload, data.length)
      payload.put(data)
    }
  }
}

sealed case class Ping(nonce: Long) extends BitcoinMessage {
  override def toByteString() = {
    BitcoinMessage.wrapPayload("ping") { payload =>
      payload.putLong(nonce)
    }
  }
}
object Ping {
  def apply(payload: Array[Byte]) = {
    BitcoinMessage.unwrapPayload(payload) { bb =>
      val nonce = bb.getLong()
      new Ping(nonce)
    }
  }
}

sealed case class Pong(nonce: Long) extends BitcoinMessage {
  override def toByteString() = {
    BitcoinMessage.wrapPayload("pong") { payload =>
      payload.putLong(nonce)
    }
  }
}
object Pong {
  def apply(payload: Array[Byte]) = {
    BitcoinMessage.unwrapPayload(payload) { bb =>
      val nonce = bb.getLong()
      new Pong(nonce)
    }
  }
}

sealed case class Notfound(inv: List[Inv]) extends BitcoinMessage
object Notfound {
  def apply(payload: Array[Byte]) = {
    BitcoinMessage.unwrapPayload(payload) { bb =>
      val count = readVarInt(bb)
      new Notfound((for (i <- 0 until count) yield Inv(bb)).toList)
    }
  }
}
sealed case class EmptyMessage(tpe: String) extends BitcoinMessage

case class GetBlocksData(hashes: Map[String, Int])

object BitcoinMessage {
  val testnet = false 
  val startingBlockScan = if (testnet) 0 else 308000
  val magic = if (testnet) 0xDAB5BFFA else 0xD9B4BEF9
  val addressVersion: Byte = if (testnet) 0x6F else 0x00
  val version = 70001
  val hashZero = "0000000000000000000000000000000000000000000000000000000000000000"
  def allocateHashBytes(): Hash = new Array(32)
  def wrapPayload(cmd: String)(ff: ByteBuffer => Unit): ByteString = {
    val bb = ByteBuffer.allocate(102400)
    bb.order(ByteOrder.LITTLE_ENDIAN)
    bb.putInt(magic)
    bb.put(Arrays.copyOf(cmd.getBytes, 12))
    val payload = ByteBuffer.allocate(102400)
    payload.order(ByteOrder.LITTLE_ENDIAN)
    ff(payload)
    payload.flip()
    bb.putInt(payload.limit)
    bb.put(BitcoinMessage.checksum(payload.array, 0, payload.limit))
    bb.put(payload.array, 0, payload.limit)
    bb.flip()
    ByteString(bb)
  } 
  def unwrapPayload[T](payload: Array[Byte])(f: ByteBuffer => T): T = {
    val bb = ByteBuffer.wrap(payload)
    bb.order(ByteOrder.LITTLE_ENDIAN)
    f(bb)
  }
  def checksum(ba: Array[Byte], offset: Int, length: Int) = {
    val sha256 = new SHA256Digest()
    val result: Array[Byte] = new Array(32)
    sha256.update(ba, offset, length)
    sha256.doFinal(result, 0)
    sha256.update(result, 0, 32)
    sha256.doFinal(result, 0)
    ArrayUtils.subarray(result, 0, 4)
  }
  def putString(bb: ByteBuffer, s: String) = {
    bb.put(s.length.toByte)
    bb.put(s.getBytes)
  }
  def currentTime() = {
    val now = DateTime.now
    val ts = now.getMillis / 1000
    ts.toInt
  }
  def networkAddress(hasTime: Boolean, address: InetSocketAddress) = {
    val bb = ByteBuffer.allocate(30)
    bb.order(ByteOrder.LITTLE_ENDIAN)
    if (hasTime)
      bb.putInt(BitcoinMessage.currentTime)
    bb.putLong(1)
    val addr = address.getAddress()
    bb.putLong(0)
    bb.putShort(0)
    bb.putShort(-1)
    bb.put(addr.getAddress())
    bb.order(ByteOrder.BIG_ENDIAN)
    bb.putShort(address.getPort.toShort)
    bb.flip()
    ArrayUtils.subarray(bb.array, 0, bb.limit)
  }
  def getNetworkAddress(bb: ByteBuffer, hasTime: Boolean): AddrRec = {
    val ts = if (hasTime) bb.getInt() else 0
    bb.getLong() // services
    bb.getLong()
    bb.getInt()
    val address: Array[Byte] = new Array(4)
    bb.get(address)
    bb.order(ByteOrder.BIG_ENDIAN)
    val port = bb.getShort()
    bb.order(ByteOrder.LITTLE_ENDIAN)
    AddrRec(ts, new InetSocketAddress(InetAddress.getByAddress(address), port.toInt & 0x7FFF))
  }
  def getString(bb: ByteBuffer) = {
    val len = bb.get()
    val s: Array[Byte] = new Array(len)
    bb.get(s)
    new String(s)
  }
  def parse(cmd: String, payload: Array[Byte]): BitcoinMessage = cmd match {
    case "version" => Version(payload)
    case "verack" => Verack()
    case "addr" => Addr(payload)
    case "getaddr" => EmptyMessage("getaddr")
    case "inv" => InvVector(payload)
    case "reject" => Reject(payload)
    case "headers" => Headers(payload)
    case "merkleblock" => MerkleBlock(payload)
    case "notfound" => Notfound(payload)
    case "ping" => Ping(payload)
    case "pong" => Pong(payload)
    case "tx" => Tx(payload)
  }
}


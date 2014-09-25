package com.spvwallet

import scala.annotation.tailrec
import scala.concurrent.duration._
import akka.stream.scaladsl2._
import akka.actor._
import akka.pattern.ask
import akka.util.{Timeout, ByteString}
import java.nio.{ByteBuffer, ByteOrder}
import org.apache.commons.lang3.ArrayUtils
import java.util.Arrays
import org.joda.time.DateTime
import akka.event.LoggingReceive
import akka.persistence.{PersistentActor, SnapshotOffer}
import org.bouncycastle.util.encoders.Hex
import akka.persistence.RecoveryCompleted
import org.bouncycastle.math.ec.ECPoint
import scala.concurrent.Await
import java.security.SecureRandom
import CryptoUtils._
import java.math.MathContext

case class TxHeight(height: Int, tx: Tx)

/**
 * Synchronizes with the blockchain
 */
class BChainSync(startingBlockScan: Int, startingHeight: Int, blockchainHeaders: List[Header], nKeys: Int, keyStream: Stream[ECPoint], peer: ActorRef) extends FSM[BChainSync.State, BChainSync.Data] with ActorLogging {
  import BChainSync._
  context watch peer

  val r = new SecureRandom()
  val bloomFilter = new BloomFilter(1000, 0.000001, 40, r.nextInt())
  
  emitFilterLoad(nKeys)

  private def emitFilterLoad(nKeys: Int) = {
    log.info("New filter with {} keys", nKeys)
    val pubKeys = keyStream.take(nKeys)
    for (pk <- pubKeys) {
      bloomFilter.addKey(pk)
    }
    peer ! bloomFilter.toFilterLoad()
  }
  private def emitGetHeaders(blockchainHeaders: List[Header]) = { 
    peer ! GetHeaders(blockchainHeaders.take(10).map(h => Hex.toHexString(h.hash)), genesisHash)
  }
  
  when(GetNewHeaders) {
    case Event(h: Headers, HeaderData(currentHeight, newBlockHeaders, nKeys, newTxs)) =>
      h.headers match {
        case Nil => // No more headers - we are done
          context.parent ! SyncResults(currentHeight, newBlockHeaders, nKeys, newTxs)
          context stop self
          stay
          
        case fh :: _ => // Got some headers, find where this new chain hooks and trim orphan blocks
          val (orphanedBlocks, nonOrphanedBlocks) = newBlockHeaders.span(bh => !CryptoUtils.compareHashes(bh.hash, fh.prevBlockHash))

          // Our chain is reversed: Most recent block is the head
          val newChain = h.headers.reverse ++ nonOrphanedBlocks
          val len = newChain.length
          // Zip with the block heights
          val hh = newChain.zipWithIndex.map { case (h, i) => Hex.toHexString(h.hash) -> (currentHeight + len - i - 1) }.toMap

          // After the starting scan height, go deep and get detailed block data
          if (currentHeight > startingBlockScan)
            peer ! GetBlocksData(hh)
          else
            self ! Nil
          goto(ScanBlocks) using ScanBlocksData(HeaderData(currentHeight, newChain, nKeys, newTxs), hh)
      }

    case Event(tx: TxHeight, hd: HeaderData) =>
      stay using hd.copy(newTxs = tx :: hd.newTxs)
  }
  
  when(ScanBlocks) {
    // Peer sent a list of txs
    case Event(result: List[TxHeight], ScanBlocksData(HeaderData(currentHeight, newBlockHeaders, nKeys, newTxs), hh)) =>
      log.info("Scan block {}", currentHeight)
      // Check if the last address was used
      // If so, get more addresses and retry
      val lastAddress = pubToAddress(keyStream(nKeys - 1))
      val lastAddressUsed = result.find(tx => tx.tx.txOuts.find(txOut => txOut.address == lastAddress).isDefined)
      if (lastAddressUsed.isDefined) {
        log.debug("New address required")
        emitFilterLoad(nKeys + BChain.addressIncrease)
        peer ! GetBlocksData(hh)
        stay using ScanBlocksData(HeaderData(currentHeight, newBlockHeaders, nKeys + BChain.addressIncrease, newTxs), hh)
      }
      else {
        // Keep the most recent headers and get more headers from peer
        // We are not interested in old headers and blocks once we have our txs
        val trimHeaders = newBlockHeaders.take(blockchainMaxLength)
        emitGetHeaders(trimHeaders)
        goto(GetNewHeaders) using HeaderData(currentHeight + newBlockHeaders.length - trimHeaders.length, trimHeaders, nKeys, result ++ newTxs)
      }

    // Received a tx from outside a block, add it to our set it's an unconfirmed tx
    case Event(tx: TxHeight, sbd: ScanBlocksData) =>
      stay using sbd.copy(d = sbd.d copy (newTxs = tx :: sbd.d.newTxs))
  }
  
  startWith(GetNewHeaders, HeaderData(startingHeight, blockchainHeaders, nKeys, Nil))
  emitGetHeaders(blockchainHeaders)
}

object BChainSync {
  val blockchainMaxLength = 50 // Keep a max of 50 headers
  trait State
  case object GetNewHeaders extends State
  case object ScanBlocks extends State
  
  trait Data
  case class HeaderData(currentHeight: Int, newBlockHeaders: List[Header], nKeys: Int, newTxs: List[TxHeight]) extends Data
  case class ScanBlocksData(d: HeaderData, hh: Map[String, Int]) extends Data

  case object Sync
  case class SyncResults(currentHeight: Int, newBlockHeaders: List[Header], nKeys: Int, txs: List[TxHeight])
}

/**
 * Persist the blockchain
 */
class BChainPersistor extends PersistentActor with ActorLogging {
  import BChainPersistor._
  def persistenceId: String = "BChain"
  var state = BChainState(0, BChain.genesisBlockchain, 1, Map.empty) 
  
  def receiveRecover: Receive = {
    case e @ Event(currentHeight, blocks, nKeys, txs, delta) => updateState(e)
    case SnapshotOffer(_, offeredSnapshot: BChainState) => state = offeredSnapshot
    case RecoveryCompleted =>
      context.parent ! state
  }
  
  def updateState(e: Event) = e match {
    case Event(currentHeight, blocks, nKeys, txs, delta) =>
      val updatedBlocks = if (delta)
        (blocks ++ state.blocks).take(BChainSync.blockchainMaxLength)
      else
        blocks
      state = state copy (currentHeight = currentHeight, blocks = updatedBlocks, nKeys = nKeys, txs = state.txs ++ txs)
  }
  def receiveCommand: Receive = {
    case BChain.Save => saveSnapshot(state)
    case BChain.ConnectedData(currentHeight, blockchainHeaders, nKeys, txs, _) =>
      // If the chain is vastly different from the previously stored one,
      // write it entirely otherwise just write the difference
      val deltaLength = currentHeight - state.currentHeight
      if (blockchainHeaders.length >= deltaLength) {
        val deltaBlocks = blockchainHeaders.take(deltaLength)
        persist(Event(currentHeight, deltaBlocks, nKeys, txs, true))(updateState)
      }
      else {
        persist(Event(currentHeight, blockchainHeaders, nKeys, txs, false))(updateState)
      }
  }
}
object BChainPersistor {
  case class BChainState(currentHeight: Int, blocks: List[Header], nKeys: Int, txs:  Map[String, TxHeight])
  case class Event(currentHeight: Int, blocks: List[Header], nKeys: Int, txs:  Map[String, TxHeight], isDelta: Boolean)
}

/**
 * BTC balance at an address
 */
case class Balance(confirmed: Long, unconfirmed: Long, txCount: Int) {
  def add(other: Balance) = Balance(confirmed + other.confirmed, unconfirmed + other.unconfirmed, txCount + other.txCount)
  def isEmpty: Boolean = confirmed == 0 && unconfirmed == 0 && txCount == 0
  private def toBTC(satoshis: Long) = (BigDecimal(satoshis, 8, MathContext.DECIMAL32)).toString()
  override def toString() = s"${toBTC(confirmed)} (${toBTC(unconfirmed)})"
}

/**
 * Blockchain Actor
 * 
 * Maintains the blockchain and our txs
 */
class BChain(masterPubKey: String, startingBlockScan: Int, peerManager: ActorRef) extends FSM[BChain.State, BChain.Data] with ActorLogging {
  import BChain._
  peerManager ! Register(self)
  val mpub = Hex.decode(masterPubKey)
  val wallet = new Electrum(None, mpub)
  val keyStream = wallet.pub.map(_.p)
  val persistor = context.actorOf(Props[BChainPersistor])
  
  private def computeBalance(watchedKeys: List[ECPoint], txs: Map[String, TxHeight]): Map[String, TxHeight] = {
    import CryptoUtils._
    
    /** 
     * Accumulates balances into a map of addresses 
     */
    case class ComputeBalanceAcc(addresses: Map[String, Balance], txs: Map[String, TxHeight])
    def processTx(tx: Iterable[TxHeight]): ComputeBalanceAcc  = {
      val addresses = watchedKeys.map(pubToAddress(_) -> Balance(0, 0, 0)).toMap
      val txMap = tx.map(tx => Hex.toHexString(tx.tx.hash) -> tx).toMap
      
      def accTx(acc: ComputeBalanceAcc, tx: TxHeight): ComputeBalanceAcc = {
        def toBalance(value: Long) = if (tx.height == 0) Balance(0, value, 1) else Balance(value, 0, 1)
        // Inputs of the tx => coins are spent
        val ins = for {
          txOut <- tx.tx.txOuts
          addr = txOut.address
          balance <- addresses.get(addr)
          value = txOut.value
        } yield addr -> toBalance(value)
        // Outputs of the tx => coins are received
        val outs = for {
          txIn <- tx.tx.txIns
          op = txIn.outpoint
          prevTx <- txMap.get(op.txHash)
          txOut = prevTx.tx.txOuts(op.index)
          addr = txOut.address
          balance <- addresses.get(addr)
          value = txOut.value
        } yield addr -> toBalance(-value)
        val inOuts = ins ++ outs
        
        val accAddresses = inOuts.foldLeft(acc.addresses){ case (addresses, (addr, value)) => 
          addresses.updated(addr, addresses(addr).add(value))
        }
        ComputeBalanceAcc(accAddresses, if (inOuts.isEmpty) acc.txs else acc.txs.updated(Hex.toHexString(tx.tx.hash), tx))
      }
      val z = ComputeBalanceAcc(addresses, Map.empty)
      tx.foldLeft(z)(accTx)
    }
    
    val ComputeBalanceAcc(balances, myTxs) = processTx(txs.values)
    val nonZeroAddresses = balances.filter(!_._2.isEmpty)
    nonZeroAddresses.foreach { case (a, b) =>
      println(s"$a\t$b")}
    val total = balances.foldLeft(Balance(0, 0, 0)){ case (acc, (k, v)) => acc.add(v) }
    val firstUnused = wallet.pub.filter(a => balances(a.addr).isEmpty && a.account == 0).map(_.addr).head
    println(s"Account balance = $total")
    println(s"Receive Address = $firstUnused")
    println("---------------------------")
    myTxs
  }
  
  private def processInvVector(inv: InvVector, peer: ActorRef) = {
    val newTxs = inv.invs.filter(_.tpe == 1) // Request detailed data of incoming txs
    if (!newTxs.isEmpty)
      peer ! GetData(newTxs)
    stay
  }

  when(Idle) {
    case Event(BChainPersistor.BChainState(currentHeight, blockchainHeaders, nKeys, txs), _) =>
      self ! ComputeBalance // Compute balance pre-connection
      stay using IdleData(currentHeight, blockchainHeaders, nKeys, txs)
    case Event(Peer.PeerReady, IdleData(currentHeight, blockchainHeaders, nKeys, txs)) =>
      val peer = sender
      context watch peer // Sign deathwatch contract with peer actor
      goto(Connected) using ConnectedData(currentHeight, blockchainHeaders, nKeys, txs, peer)
  }
  
  when(Connected) {
    case Event(BChainSync.Sync, ConnectedData(currentHeight, blockchainHeaders, nKeys, txs, peer)) =>
      val syncActor = context.actorOf(Props(new BChainSync(startingBlockScan, currentHeight, blockchainHeaders, nKeys, keyStream, peer)), "SYNC")
      goto(Syncing) using SyncingData(blockchainHeaders, nKeys, txs, peer, syncActor)
  }
  
  when(Syncing) {
    // Synced - Emit report and update
    case Event(results: BChainSync.SyncResults, SyncingData(blockchainHeaders, nKeys, txs, peer, _)) =>
      log.info("BChain = {}/{}", results.currentHeight + results.newBlockHeaders.length - 1, results.newBlockHeaders.head)
      val updatedTxs = (txs ++ results.txs.map(tx => Hex.toHexString(tx.tx.hash) -> tx))
      self ! ComputeBalance
      val data = ConnectedData(results.currentHeight, results.newBlockHeaders, results.nKeys, updatedTxs, peer)
      persistor ! data
      goto(Connected) using data
    case Event(BChainSync.Sync, _) => stay // Ignore sync requests while syncing
    case Event(inv: InvVector, syncData: SyncingData) =>
      processInvVector(inv, syncData.peer) // Only process new tx while syncing
    case Event(x, d: SyncingData) => // Forward the rest to the synchronizing actor
      d.syncActor ! x
      stay
  }
  
  whenUnhandled {
    case Event(s @ BChain.Save, _) =>
      persistor ! s
      stay
      
    case Event(ComputeBalance, ConnectedData(currentHeight, blockchainHeaders, nKeys, txs, peer)) =>
      val keys = keyStream.take(nKeys).toList
      val myTxs = computeBalance(keys, txs)
      stay using ConnectedData(currentHeight, blockchainHeaders, nKeys, myTxs, peer)
    case Event(ComputeBalance, IdleData(currentHeight, blockchainHeaders, nKeys, txs)) =>
      val keys = keyStream.take(nKeys).toList
      computeBalance(keys, txs)
      stay
    case Event(inv: InvVector, connectedData: ConnectedData) =>
      if (inv.invs.exists(_.tpe == 2)) // Inventory block => Start syncing to new blockchain
        self ! BChainSync.Sync
      processInvVector(inv, connectedData.peer)
        
    case Event(tx: TxHeight, ConnectedData(currentHeight, blockchainHeaders, nKeys, txs, peer)) =>
      val txHash = Hex.toHexString(tx.tx.hash)
      self ! ComputeBalance
      stay using ConnectedData(currentHeight, blockchainHeaders, nKeys, txs.updated(txHash, txs.getOrElse(txHash, tx)), peer)

    case Event(Terminated(_), ConnectedData(currentHeight, blockchainHeaders, nKeys, txs, peer)) =>
      println("SYNC ABORTED")
      goto(Idle) using IdleData(currentHeight, blockchainHeaders, nKeys, txs)
  }
  
  onTransition {
    case Idle -> Connected =>
      self ! BChainSync.Sync
  }
  
  startWith(Idle, IdleData(0, genesisBlockchain, 1, Map.empty))
  initialize()
}

object BChain {
  trait State
  case object Idle extends State
  case object Connected extends State
  case object Syncing extends State
  
  trait Data
  case class IdleData(currentHeight: Int, blockchainHeaders: List[Header], nKeys: Int, txs:  Map[String, TxHeight]) extends Data
  case class ConnectedData(currentHeight: Int, blockchainHeaders: List[Header], nKeys: Int, txs:  Map[String, TxHeight], peer: ActorRef) extends Data
  case class SyncingData(blockchainHeaders: List[Header], nKeys: Int, txs:  Map[String, TxHeight], peer: ActorRef, syncActor: ActorRef) extends Data
  
  case object OnConnection
  case object Synced
  case object ComputeBalance
  case object Save

  val genesisBlockchain = List(Header(Hex.decode(CryptoUtils.genesisHash), 0, Array(), Array(), 0, 0, 0))
  val addressIncrease = 100
  
  def main(args: Array[String]) {
    if (args.length < 2) {
      println("Usage: <master pub key> <starting height for scan>")
    }
    else {
      val system = ActorSystem()
      val pm = system.actorOf(Props[PeerManager], "PeerManager")
      val bchain = system.actorOf(Props(new BChain(args(0), args(1).toInt, pm)), "BChain")
  
      Console.println("Click in this console and press ENTER to exit.")
      System.in.read()
      
      bchain ! BChain.Save
      pm ! PeerManager.Save
      system.shutdown()
      
      println("Quitting.")
    }
  }
}
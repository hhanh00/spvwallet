package com.spvwallet

import scala.concurrent.duration._
import akka.io.IO
import akka.stream.io.StreamTcp
import akka.stream.actor.{ActorPublisher, ActorPublisherMessage}
import akka.stream.scaladsl2._
import java.net.{InetSocketAddress, Inet4Address, InetAddress}
import akka.pattern.ask
import akka.actor._
import akka.util.{Timeout, ByteString}
import java.nio.{ByteBuffer, ByteOrder}
import org.apache.commons.lang3.ArrayUtils
import java.util.Arrays
import org.joda.time.DateTime
import scala.annotation.tailrec
import akka.event.LoggingReceive
import akka.persistence.{PersistentActor, SnapshotOffer}
import akka.stream.Transformer
import org.reactivestreams.{Publisher, Subscriber}
import org.bouncycastle.util.encoders.Hex
import scala.collection.mutable.HashMap
import akka.persistence.RecoveryCompleted
import akka.io.Tcp.{CommandFailed, Connect}
import akka.actor.Status.Failure
import scala.io.Source
import java.net.InetSocketAddress
import java.security.SecureRandom
import akka.stream.scaladsl2.OnCompleteSink

case class Register(actor: ActorRef)

/**
 * Accumulates chunks of data into a list of raw messages
 * 
 * TCP/IP can split bitcoin messages into multiple parts or a TCP/IP packet
 * can contain multiple bitcoin messages
 */
class PacketTransformer extends Transformer[ByteString, BitcoinMessage] {
  val headerLen = 24
  var currentChunk = ByteString()
  var currentPayloadLength: Int = _
  var inHeader = true // true if decoding header
  var cmd = ""
  
  override def onNext(in: ByteString) = {
    currentChunk ++= in

    @tailrec
    def acc(a: List[BitcoinMessage]): List[BitcoinMessage] = {
      val bb = currentChunk.asByteBuffer
      
      if (inHeader) {
        if (currentChunk.length > headerLen) {
          bb.order(ByteOrder.LITTLE_ENDIAN)
          val magic = bb.getInt()
          assert(magic == BitcoinMessage.magic)
          val command: Array[Byte] = new Array(12)
          bb.get(command)
          cmd = new String(command).trim()
          currentPayloadLength = bb.getInt()
          val checksum = bb.getInt()
          currentChunk = currentChunk.drop(headerLen)
          inHeader = false
          acc(a)
        }
        else a
      }
      else {
        if (bb.remaining >= currentPayloadLength) {
          val payload: Array[Byte] = new Array(currentPayloadLength)
          bb.get(payload)
          currentChunk = currentChunk.drop(currentPayloadLength)
          currentPayloadLength = 0
          inHeader = true
          val m = BitcoinMessage.parse(cmd, payload)
          acc(m :: a)
        }
        else a          
      }
    }
    
    acc(Nil)
  }
}

/**
 * Publish data onto a reactive stream
 * 
 * Buffers unless the downstream components ask for data so that they are
 * not flooded
 */
class Pub[T] extends ActorPublisher[T] with ActorLogging {
  implicit val ec = context.dispatcher
  var buffer = Vector.empty[T]
  def receive() = LoggingReceive {
    case ActorPublisherMessage.Request(_) => publishBuffer()
    case t: T => publish(t) 
  }
  
  def publish(t: T) = {
    if (totalDemand > 0 && buffer.isEmpty)
      send(t)
    else {
      buffer :+= t
      publishBuffer()
      }
  }

  def publishBuffer() = {
    if (totalDemand > 0) {
      val (toSend, toKeep) = buffer.splitAt(totalDemand.toInt)
      buffer = toKeep
      toSend.foreach(send)
    }
  }
  
  def send(t: T) = onNext(t)
}

/**
 * Persists the addresses received from peers
 */
class PeerManagerPersistor extends PersistentActor {
  def persistenceId: String = "PeerManager"
  
  var state = (for (seed <- Source.fromInputStream(getClass().getResourceAsStream("/seeds.txt")).getLines()) 
    yield seed -> AddrRec(0, new InetSocketAddress(seed, 8333))).toMap
  
  def updateState(addr: AddrRec) = {
    state += addr.address.getHostString -> addr
  }
  def removeAddr() = state = state.tail
  
  def receiveRecover: Receive = {
    case addr: AddrRec => updateState(addr)
    case PeerManager.RemoveAddr => removeAddr() 
       
    case SnapshotOffer(_, offeredSnapshot: Map[String, AddrRec]) => 
      state = offeredSnapshot
    case RecoveryCompleted =>
      context.parent ! state
  }
  def receiveCommand: Receive = {
    case PeerManager.Save => saveSnapshot(state)
    case r @ PeerManager.RemoveAddr =>
      persist(r)(_ => removeAddr())
    case addr: AddrRec =>
      persist(addr)(updateState)
  }
}

/**
 * Maintains a list of peer addresses and tries to connect to one of them
 * In addition, binds a listening socket for incoming connections
 */
class PeerManager extends FSM[PeerManager.State, PeerManager.Data] with Stash {
  import PeerManager._
  implicit val materializer = FlowMaterializer()
  implicit val s = context.system
  implicit val ec = context.dispatcher
  implicit val timeout = Timeout(5.minute)
  
  val persistor = context.actorOf(Props[PeerManagerPersistor])
  private val localAddress = new InetSocketAddress(InetAddress.getLocalHost, 7333)

  // Wait for the blockchain handler to register itself
  when(Uninitialized) {
    case Event(addrs: Map[String, AddrRec], _) =>
      unstashAll()
      goto(Unregistered) using UnregisteredData(addrs)
    case _ => 
      stash()
      stay
  }
  
  // Bind the listening socket
  when(Unregistered) {
    case Event(Register(blockchainActor), UnregisteredData(addrs)) => 
      IO(StreamTcp) ! StreamTcp.Bind(localAddress)
      goto(Prebound) using PreboundData(blockchainActor, addrs)
  }
  
  // Wait for the binding
  when(Prebound) {
    case Event(binding: StreamTcp.TcpServerBinding, PreboundData(blockchainActor, addrs)) =>
      FlowFrom(binding.connectionStream).map { connection =>
        log.info("Incoming connection from {}", connection.remoteAddress)
        self ! connection
        self ! Addr(List(AddrRec(0, connection.remoteAddress)))
      }.consume()
      goto(Disconnected) using DisconnectedData(binding, blockchainActor, addrs)
  }
  
  // Now switch between Disconnected & Connected states depending on whether we are connected
  // to a peer
  when(Disconnected) {
    case Event(connection: StreamTcp.IncomingTcpConnection, DisconnectedData(binding, blockchainActor, addrs)) =>
      val name = connection.remoteAddress.getHostString
      log.info(s"Connected to $name")
      val peer = context.actorOf(Props(new Peer(blockchainActor, name, binding.localAddress, connection.remoteAddress, connection.inputStream, connection.outputStream, false)))
      context watch peer
      goto(Connected) using ConnectedData(binding, blockchainActor, addrs, peer)

    case Event(connection: StreamTcp.OutgoingTcpConnection, DisconnectedData(binding, blockchainActor, addrs)) =>
      val name = connection.remoteAddress.getHostString
      log.info(s"Connected to $name")
      val peer = context.actorOf(Props(new Peer(blockchainActor, name, connection.localAddress, connection.remoteAddress, connection.inputStream, connection.outputStream, false)))
      context watch peer
      goto(Connected) using ConnectedData(binding, blockchainActor, addrs, peer)

    case Event(Failure(t), DisconnectedData(binding, blockchainActor, addrs)) =>
      log.debug("Connection failed {}", t)
      // Pick the next address available
      connectOne(addrs.tail)
      persistor ! RemoveAddr
      goto(Disconnected) using DisconnectedData(binding, blockchainActor, addrs.tail)
  }
  
  when(Connected) {
    case Event(addr: Addr, ConnectedData(binding, blockchainActor, addrs, peer)) =>
      // Store new addresses
      val addrNames = addr.addrs.map(a => a.address.getHostString -> a)
      addr.addrs.map(persistor ! _) 
      stay using ConnectedData(binding, blockchainActor, addrs ++ addrNames, peer)
      
    case Event(Terminated(_), ConnectedData(binding, blockchainActor, addrs, _)) =>
      // Peer disconnected or closed, switch to Disconnected
      goto(Disconnected) using DisconnectedData(binding, blockchainActor, addrs)
      
    case Event(s @ PeerManager.Save, _) => 
      persistor ! s
      stay

    case Event(e, ConnectedData(_, blockchainActor, _, _)) =>
      // Forward messages to the blockchain handler
      // Catches all remaining messages so the whenUnhandled will not be called
      blockchainActor ! e
      stay
  }

  onTransition {
    case Prebound -> Disconnected =>
      val state = stateData.asInstanceOf[PreboundData]
      connectOne(state.addrs)
      
    case Connected -> Disconnected =>
      val state = stateData.asInstanceOf[ConnectedData]
      connectOne(state.addrs)
  }
  
  whenUnhandled {
    case Event(s @ PeerManager.Save, _) => 
      persistor ! s
      stay
  }
  
  startWith(Uninitialized, NoData)
  
  private def connectOne(addrs: Map[String, AddrRec]) = {
    addrs.headOption.foreach { a =>
      log.info("Attempting connection to {}", a._2.address)
      IO(StreamTcp) ! StreamTcp.Connect(a._2.address)}
  }
}
object PeerManager {
  trait State
  case object Uninitialized extends State
  case object Unregistered extends State
  case object Prebound extends State
  case object Disconnected extends State
  case object Connected extends State
  
  trait Data
  case object NoData extends Data
  case class UnregisteredData(addrs: Map[String, AddrRec]) extends Data
  case class PreboundData(blockchainActor: ActorRef, addrs: Map[String, AddrRec]) extends Data
  case class DisconnectedData(binding: StreamTcp.TcpServerBinding, blockchainActor: ActorRef, addrs: Map[String, AddrRec]) extends Data
  case class ConnectedData(binding: StreamTcp.TcpServerBinding, blockchainActor: ActorRef, addrs: Map[String, AddrRec], peer: ActorRef) extends Data
  
  case object Save
  case class RemoveAddr(name: String)
}

/**
 * Handles communication with the Bitcoin network
 * 
 * Process low level protocol messages and forward high level messages to the
 * blockchain actor
 */
class Peer(blockchainActor: ActorRef, name: String, local: InetSocketAddress, remote: InetSocketAddress, inputStream: Publisher[ByteString], outputStream: Subscriber[ByteString], inbound: Boolean) 
  extends FSM[Peer.State, Peer.Data] with Stash with ActorLogging {
  import Peer._
  
  implicit val ec = context.dispatcher
  context.system.scheduler.schedule(1.minute, 1.minute, self, Png)
  
  log.info("Peer connected {} {} -> {}", name, local.getHostString, remote.getHostString)
  implicit val materializer = FlowMaterializer()
  val pubActor = context.actorOf(Props[Pub[BitcoinMessage]])
  
  FlowFrom(inputStream).transform("unchunk", () => new PacketTransformer()).map { p =>
    self ! p
  }.withSink(OnCompleteSink {
    case scala.util.Success(_) =>
    case scala.util.Failure(t) => context stop self // Stop ourselves if the pipeline breaks
  }).run()
  FlowFrom(ActorPublisher[BitcoinMessage](pubActor)).map(_.toByteString).publishTo(outputStream)
  if (!inbound)
    pubActor ! Version(0, remote, local)
  
  // Exchange version handshake - No further communication can be done prior, so save all
  // incoming messages until then
  when(BeforeHandshake) {
    case Event(v: Version, _) =>
      if (inbound)
        pubActor ! Version(0, v.remote, v.local) // TODO: Pass current blockchain height?
      pubActor ! Verack()
      stay
    case Event(_: Verack, _) =>
      pubActor ! GetAddr()
      unstashAll()
      blockchainActor ! PeerReady
      goto(BeforeFilter)
    case Event(_, _) => 
      stash()
      stay
  }
  
  // Send the bloom filter - See BIP 37 for more info
  // Don't do anything before the filter is established or
  // we could be flooded with all the transactions
  when(BeforeFilter) {
    case Event(fl: FilterLoad, _) => 
      pubActor ! fl
      unstashAll()
      goto(Normal)
      
    case Event(_, _) => 
      stash()
      stay
  }
  
  // Normal state
  when(Normal) {
    case Event(fl: FilterLoad, _) => 
      pubActor ! fl
      stay
    case Event(h: Headers, _) => 
      blockchainActor ! h
      stay
    case Event(gh: GetHeaders, _) => 
      pubActor ! gh
      stay
    case Event(gb: GetBlocksData, _) => 
      val gd = GetData(gb.hashes.map(h => Inv(3, Hex.decode(h._1))).toList)
      pubActor ! gd
      goto(InGetData) using PendingGetData(sender, gb.hashes, Set.empty, Map.empty, gb.hashes.keys.toSet, Nil, Map.empty)
    case Event(gd: GetData, _) => 
      pubActor ! gd
      stay
    case Event(tx: Tx, _) => 
      blockchainActor ! TxHeight(0, tx)
      stay
  }
  
  // Getting detailed content from blocks
  // The remote node sends a filtered blocks and filtered transactions. Tx not part of the node memory
  // pool are sent before the merkle block. Missing tx must be requested seperately.
  // Go back to normal state when we received every tx mentioned in merkle blocks
  when(InGetData) {
    case Event(tx: Tx, PendingGetData(sender, blocks, pendingTx, completedTx, pendingBlocks, completedBlocks, txHash2block))  => 
      // println(tx)
      val txHash = Hex.toHexString(tx.hash)
      continueGetData(PendingGetData(sender, blocks, pendingTx - txHash, completedTx.updated(txHash, tx), pendingBlocks, completedBlocks, txHash2block))
      
    case Event(mb: MerkleBlock, PendingGetData(sender, blocks, pendingTx, completedTx, pendingBlocks, completedBlocks, txHash2block)) =>
      // println(mb)
      val hash = Hex.toHexString(mb.header.hash)
      assert(pendingBlocks.contains(hash))
      val uncompletedTxHash = mb.txHashes.toSet -- completedTx.keys
      continueGetData(PendingGetData(sender, blocks, pendingTx ++ uncompletedTxHash, completedTx, pendingBlocks - hash, mb :: completedBlocks, 
          txHash2block ++ mb.txHashes.map(txHash => txHash -> Hex.toHexString(mb.header.hash))))
  }
  
  // Check if more data
  when(ContinueGetData) {
    case Event(true, _) => goto(InGetData)
    case Event(false, _) => goto(Normal)
  }

  def continueGetData(pendingData: PendingGetData) = pendingData match {
    case PendingGetData(sender, blocks, pendingTx, completedTx, pendingBlocks, completedBlocks, txHash2block) => 
      if (pendingBlocks.isEmpty) {
        if (!pendingTx.isEmpty) {
          val gd = GetData(pendingTx.map(h => Inv(1, Hex.decode(h))).toList)
          pubActor ! gd // Send get data for the remaining tx
          goto(InGetData) using pendingData
        }
        else {
          // Package the result as pairs of tx + height
          val result = completedTx.values.map { tx => 
            val txHash = Hex.toHexString(tx.hash)
            val h = for (blockHash <- txHash2block.get(txHash);
               height <- blocks.get(blockHash)) yield height
            TxHeight(h.getOrElse(0), tx)
          }.toList
          blockchainActor ! result
          goto(Normal) using NoData
        }
      }
      else
        goto(InGetData) using pendingData
  }

  val r = new SecureRandom()
  whenUnhandled {
    case Event(Png, _) =>
      pubActor ! Ping(r.nextLong())
      stay
    
    case Event(addr: Addr, _) =>
      context.parent ! addr
      stay
      
    case Event(inv: InvVector, _) =>
      blockchainActor ! inv
      stay
      
    case Event(Ping(nonce), _) => 
      pubActor ! Pong(nonce)
      stay

    case Event(Pong(_), _) => stay
  }
  
  startWith(BeforeHandshake, NoData) 
}
object Peer {
  trait State
  case object BeforeHandshake extends State
  case object BeforeFilter extends State
  case object Normal extends State
  case object InGetData extends State
  case object ContinueGetData extends State
  
  trait Data
  case object NoData extends Data
  case class PendingGetData(sender: ActorRef, blocks: Map[String, Int], pendingTx: Set[String], completedTx: Map[String, Tx], pendingBlocks: Set[String], completedBlocks: List[MerkleBlock],
    txHash2block: Map[String, String]) extends Data

  object Png
  case object PeerReady
}

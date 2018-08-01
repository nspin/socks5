{-# LANGUAGE ScopedTypeVariables #-}

module Network.Socks5.Conduit
    ( socksServer
    ) where

import Control.Concurrent.Async
import Control.Monad.Catch
import Control.Monad.IO.Unlift
import Control.Monad.Trans
import Control.Monad.Trans.Resource
import Data.ByteString (ByteString)
import Data.Conduit
import Data.Conduit.Network
import Data.Conduit.Serialize
import Data.Streaming.Network
import Network.Socket (Socket, SockAddr, close)
import Network.Socks5
import Network.Socks5.Socket


socksServer :: (MonadUnliftIO m, MonadCatch m, MonadThrow m) => ServerSettings -> m ()
socksServer serverSettings =
    runGeneralTCPServer serverSettings $ \appData ->
        runResourceT $ do
            (fromClient, (sock, addr)) <- appSource appData $$+ socksServerConnect (liftIO . appWrite appData)
            withRunInIO $ \run -> concurrently_
                (run (sourceSocket sock `connect` appSink appData))
                (run (fromClient $$+- sinkSocket sock))


socksServerConnect :: (MonadUnliftIO m, MonadCatch m, MonadThrow m, MonadResource m) => (ByteString -> m ()) -> ConduitT ByteString o m (Socket, SockAddr)
socksServerConnect send = do
    socksServerAuthenticate SocksServerAuthenticationPreferenceNone ctx
    req <- socksRecv ctx
    case req of
        SocksRequest SocksCommandConnect endpoint@(SocksEndpoint (SocksHostName host) port) -> do
            r <- tryC $ allocate (getSocketTCP host (fromIntegral port)) (close . fst)
            case r of
                Left (ex :: SomeException) -> end SocksReplyFailureHostUnreachable
                Right (_, (sock, addr)) -> do
                    bind <- maybe
                        (throwM (SocksInternalError "bad sockaddr"))
                        return
                        (socksEndpointFromSockAddr addr)
                    socksSend ctx $ SocksResponse (Right bind)
                    return (sock, addr)
        SocksRequest SocksCommandConnect _ -> end SocksReplyFailureAddrTypeNotSupported
        SocksRequest _                   _ -> end SocksReplyFailureCommandNotSupported
  where
    ctx = SocksContext (lift . send) sinkGet throwM
    end ex = do
        socksSend ctx $ SocksResponse (Left ex)
        socksThrow ctx $ SocksReplyFailureException ex

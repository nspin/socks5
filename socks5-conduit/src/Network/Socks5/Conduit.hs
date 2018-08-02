{-# LANGUAGE ScopedTypeVariables #-}

module Network.Socks5.Conduit
    ( socksClient
    , socksServer
    , socksServerConnect
    , liftServerAuthenticationPreference
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

socksClient :: (MonadUnliftIO m, MonadCatch m, MonadThrow m) => SocksClientAuthenticationPreference -> ClientSettings -> SocksEndpoint -> (SocksEndpoint -> (ByteString -> IO ()) -> ConduitT ByteString Void m a) -> m a
socksClient pref set endpoint f = runGeneralTCPClient set $ \appData -> do
    let ctx = SocksContext send sinkGet throwM
        send = liftIO . appWrite appData
    (fromServer, bound) <- appSource appData $$+ socksClientConnect ctx pref endpoint
    fromServer $$+- f bound (appWrite appData)

socksServer :: (MonadUnliftIO m, MonadCatch m, MonadThrow m) => SocksServerAuthenticationPreference m -> ServerSettings -> m ()
socksServer pref set = runGeneralTCPServer set $ \appData -> runResourceT $ do
    (fromClient, (sock, addr)) <- appSource appData $$+ socksServerConnect (liftServerAuthenticationPreference pref) (liftIO . appWrite appData)
    withRunInIO $ \run -> concurrently_
        (run (sourceSocket sock `connect` appSink appData))
        (run (fromClient $$+- sinkSocket sock))

socksServerConnect :: (MonadUnliftIO m, MonadCatch m, MonadThrow m, MonadResource m) => SocksServerAuthenticationPreference m -> (ByteString -> m ()) -> ConduitT ByteString o m (Socket, SockAddr)
socksServerConnect pref send = do
    socksServerAuthenticate ctx (liftServerAuthenticationPreference pref)
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

liftServerAuthenticationPreference :: (MonadTrans t, Monad m) => SocksServerAuthenticationPreference m -> SocksServerAuthenticationPreference (t m)
liftServerAuthenticationPreference = mapServerAuthenticationPreference (fmap lift)

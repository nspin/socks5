{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.Socks5.Conduit
    ( socksClient
    , socksServer
    ) where

import Control.Concurrent.Async
import Control.Exception (IOException)
import Control.Monad.Catch
import Control.Monad.Except
import Control.Monad.IO.Unlift
import Control.Monad.Trans
import Control.Monad.Trans.Resource
import Data.ByteString (ByteString)
import Data.Conduit
import Data.Acquire
import Data.Conduit.Lift (runExceptC)
import Data.Conduit.Network
import Data.Conduit.Serialize
import Data.Streaming.Network
import Network.Socket (Socket, SockAddr, close)
import Network.Socks5
import Network.Socks5.Socket

socksClient :: (MonadUnliftIO m, MonadThrow m)
            => SocksClientAuthenticationPreference
            -> ClientSettings
            -> SocksEndpoint
            -> (SocksEndpoint
            -> (ByteString -> IO ()) -> ConduitT ByteString Void m a)
            -> m a
socksClient pref set endpoint f = runGeneralTCPClient set $ \appData -> do
    let ctx = SocksContext send sinkGet throwM
        send = liftIO . appWrite appData
    (fromServer, bound) <- appSource appData $$+ socksClientConnect ctx pref endpoint
    fromServer $$+- f bound (appWrite appData)

socksServer :: (MonadUnliftIO m, MonadThrow m) => SocksServerAuthenticationPreference m -> ServerSettings -> m ()
socksServer pref set = runGeneralTCPServer set $ \appData -> runResourceT $ do
    (fromClient, (_, sock)) <- appSource appData $$+ socksServerConnect (liftServerAuthenticationPreference pref) appData
    withRunInIO $ \run -> concurrently_
        (run (sourceSocket sock `connect` appSink appData))
        (run (fromClient $$+- sinkSocket sock))

socksServerConnect :: (MonadThrow m, MonadResource m)
                   => SocksServerAuthenticationPreference m
                   -> AppData
                   -> ConduitT ByteString o m (ReleaseKey, Socket)
socksServerConnect pref appData = do
    endpoint <- socksServerAuthenticateConnect ctx (liftServerAuthenticationPreference pref)
    (key, m) <- allocateAcquire (socksAcquireSocket endpoint)
    case m of
        Nothing -> socksServerFailure ctx SocksReplyFailureHostUnreachable
        Just (local, sock) -> (key, sock) <$ socksServerSuccess ctx local
  where
    ctx = SocksContext (liftIO . appWrite appData) sinkGet throwM

socksAcquireSocket :: SocksEndpoint -> Acquire (Maybe (SocksEndpoint, Socket))
socksAcquireSocket endpoint = mkAcquire (socksConnectSocket endpoint) $ \m -> case m of
    Nothing -> return ()
    Just (_, sock) -> close sock

liftServerAuthenticationPreference :: (MonadTrans t, Monad m) => SocksServerAuthenticationPreference m -> SocksServerAuthenticationPreference (t m)
liftServerAuthenticationPreference = mapServerAuthenticationPreference (fmap lift)

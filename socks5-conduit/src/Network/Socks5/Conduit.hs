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
import Data.Conduit.Network
import Data.Conduit.Serialize
import Data.Streaming.Network
import Network.Socket (Socket)
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
    (fromClient, (_, sock)) <- appSource appData $$+ socksServerConnect
        (liftServerAuthenticationPreference2 pref)
        (return . return)
        (SocksContext (liftIO . appWrite appData) sinkGet throwM)
    withRunInIO $ \run -> concurrently_
        (run (sourceSocket sock `connect` appSink appData))
        (run (fromClient $$+- sinkSocket sock))

liftServerAuthenticationPreference :: (MonadTrans t, Monad m) => SocksServerAuthenticationPreference m -> SocksServerAuthenticationPreference (t m)
liftServerAuthenticationPreference = mapServerAuthenticationPreference (fmap lift)

liftServerAuthenticationPreference2 :: (Monad m, MonadTrans t0, Monad (t0 m), MonadTrans t1) => SocksServerAuthenticationPreference m -> SocksServerAuthenticationPreference (t1 (t0 m))
liftServerAuthenticationPreference2 = liftServerAuthenticationPreference . liftServerAuthenticationPreference

{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.Socks5.Conduit
    ( socksClient
    , socksServer
    ) where

import Network.Socks5
import Network.Socks5.Socket

import Control.Concurrent.Async
import Control.Monad.Catch
import Control.Monad.Except
import Control.Monad.IO.Unlift
import Control.Monad.Trans.Resource
import Data.Acquire
import Data.ByteString (ByteString)
import Data.Conduit
import Data.Conduit.Network
import Data.Conduit.Serialize
import Data.Streaming.Network
import Network.Socket (Socket)


socksClient :: (MonadUnliftIO m, MonadThrow m)
            => ClientSettings
            -> Maybe SocksUsernamePassword
            -> SocksEndpoint
            -> (SocksEndpoint -> (ByteString -> IO ()) -> ConduitT ByteString Void m a)
            -> m a
socksClient set mcreds endpoint f = runGeneralTCPClient set $ \appData -> do
    let ctx = SocksContext send sinkGet throwM
        send = liftIO . appWrite appData
    (fromServer, bound) <- appSource appData $$+
        (maybe (socksClientAuthenticateNone ctx) (socksClientAuthenticateUsernamePassword ctx) mcreds
                    >> socksClientCommand ctx SocksCommandConnect endpoint)
    fromServer $$+- f bound (appWrite appData)

socksServer :: (MonadUnliftIO m, MonadThrow m)
            => ServerSettings
            -> Maybe SocksUsernamePassword
            -> m ()
socksServer set mcreds = runGeneralTCPServer set $ \appData -> runResourceT $ do
    (fromClient, (_, sock)) <- appSource appData $$+ socksServerConnect
        (SocksContext (liftIO . appWrite appData) sinkGet throwM)
        mcreds
    withRunInIO $ \run -> concurrently_
        (run (sourceSocket sock `connect` appSink appData))
        (run (fromClient $$+- sinkSocket sock))

socksServerConnect :: MonadResource m => SocksContext m -> Maybe SocksUsernamePassword -> m (ReleaseKey, Socket)
socksServerConnect ctx mcreds = do
    SocksRequest cmd remote <- case mcreds of
        Nothing -> socksServerAuthenticateNone ctx
        Just creds -> do
            creds' <- socksServerGetUsernamePassword ctx
            if creds' == creds
              then socksServerUsernamePasswordSuccess ctx
              else socksServerUsernamePasswordFailure ctx
    when (cmd /= SocksCommandConnect) $
        socksServerFailure ctx SocksReplyFailureCommandNotSupported
    (key, m) <- allocateAcquire (socksAcquireSocket remote)
    case m of
        Nothing -> socksServerFailure ctx SocksReplyFailureHostUnreachable
        Just (sock, local) -> (key, sock) <$ socksServerSuccess ctx local

{-# LANGUAGE OverloadedStrings #-}

import Network.Socks5
import Network.Socks5.Conduit (socksClient, socksServer)

import Control.Monad (replicateM_)
import Control.Monad.Trans.Class (lift)
import Data.ByteString.Char8 (pack)
import Data.Conduit.Combinators (stdout)
import Data.Conduit.Network (clientSettings, serverSettings)
import System.CPUTime (getCPUTime)

main :: IO ()
-- main = torSocksClient
main = authLoggingServer

torSocksClient :: IO ()
torSocksClient = replicateM_ 10 $ do
    t <- getCPUTime
    let creds = SocksUsernamePassword (pack (show t)) "hunter2"
    socksClient set (Just creds) endpoint $ \_ send -> do
        let sendLine line = lift $ send line >> send "\r\n"
        sendLine "GET / HTTP/1.1"
        sendLine "Host: ipecho.nickspinale.com"
        sendLine "Connection: close"
        sendLine ""
        stdout
  where
    set = clientSettings 9050 "localhost"
    endpoint = SocksEndpoint (SocksHostName "ipecho.nickspinale.com") 80

authLoggingServer :: IO ()
authLoggingServer = socksServer
    (serverSettings 8080 "*")
    (Just ((>> return True) . print))

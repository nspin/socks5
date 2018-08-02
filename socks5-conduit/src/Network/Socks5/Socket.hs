{-# LANGUAGE ScopedTypeVariables #-}

module Network.Socks5.Socket
    ( socksConnectSocket
    , socksEndpointFromSockAddr
    , unsafeSocksEndpointFromSockAddr
    ) where

import Network.Socket
import Network.Socks5.Types
import Data.Maybe (fromMaybe)
import Data.ByteString.Char8 (pack, unpack)
import Network.Socket
import Control.Exception (IOException, catch, bracketOnError)

socksEndpointFromSockAddr :: SockAddr -> Maybe SocksEndpoint
socksEndpointFromSockAddr (SockAddrInet port host) = Just $ SocksEndpoint (SocksHostIPv4 host) (fromIntegral port)
socksEndpointFromSockAddr (SockAddrInet6 port _ (a, b, c, d) _) = Just $ SocksEndpoint (SocksHostIPv6 a b c d) (fromIntegral port)
socksEndpointFromSockAddr _ = Nothing

-- | For when you're sure that SocksAddr is an IP address
unsafeSocksEndpointFromSockAddr :: SockAddr -> SocksEndpoint
unsafeSocksEndpointFromSockAddr = fromMaybe (error "Network.Socks5.Socket.unsafeSocksEndpointFromSockAddr: SockAddr was SockAddrUnix")
    . socksEndpointFromSockAddr

socksConnectSocket :: SocksEndpoint -> IO (Maybe (SocksEndpoint, Socket))
socksConnectSocket (SocksEndpoint host port) = do
    infos <- case host of
        SocksHostIPv4 w -> return [(AF_INET, 0, SockAddrInet (fromIntegral port) w)]
        SocksHostIPv6 a b c d -> return [(AF_INET6, 0, SockAddrInet6 (fromIntegral port) 0 (a, b, c, d) 0)]
        SocksHostName name ->
            let f addrInfo = (addrFamily addrInfo, addrProtocol addrInfo, addrAddress addrInfo)
            in fmap (map f) $ getAddrInfo (Just hints) (Just (unpack name)) (Just (show port))
    go infos
  where
    hints = defaultHints
        { addrFlags = [AI_ADDRCONFIG]
        , addrSocketType = Stream
        , addrFamily = AF_UNSPEC
        }
    go [] = return Nothing
    go (i:is) = (Just <$> attempt i) `catch` \(_ :: IOException) -> go is
    mksock family service = do
        sock <- socket family Stream service
        setSocketOption sock NoDelay 1
        return sock
    attempt (family, service, remote) = bracketOnError (mksock family service) close $ \sock -> do
        connect sock remote
        local <- getSocketName sock
        return (unsafeSocksEndpointFromSockAddr local, sock)

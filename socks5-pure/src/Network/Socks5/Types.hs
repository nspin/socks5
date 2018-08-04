module Network.Socks5.Types
    (

    -- * Types
      SocksMethod(..)
    , SocksUsernamePassword(..)
    , SocksCommand(..)
    , SocksEndpoint(..)
    , SocksHost(..)
    , SocksPort
    , SocksReplyFailure(..)
    , SocksUdpFragmentNumber

    -- * Messages
    , SocksMethodRequest(..)
    , SocksMethodResponse(..)
    , SocksUsernamePasswordRequest(..)
    , SocksUsernamePasswordResponse(..)
    , SocksRequest(..)
    , SocksResponse(..)
    , SocksUdpRequest(..)

    ) where

import           Control.Monad (when, replicateM)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B (length)
import           Data.Foldable (traverse_)
import           Data.Serialize
import           Data.Word (Word8, Word16, Word32)


data SocksMethod =
      SocksMethodNone
    | SocksMethodGSSAPI
    | SocksMethodUsernamePassword
    | SocksMethodOther !Word8 -- 0x03 <= x < 0xFF
    deriving (Show, Eq)

data SocksUsernamePassword = SocksUsernamePassword
    { socksUsername :: ByteString
    , socksPassword :: ByteString
    } deriving (Show, Eq)

data SocksCommand =
      SocksCommandConnect
    | SocksCommandBind
    | SocksCommandUdpAssociate
    deriving (Show, Eq)

data SocksEndpoint = SocksEndpoint
    { socksHost :: SocksHost
    , socksPort :: SocksPort
    } deriving (Show, Eq)

data SocksHost =
      SocksHostIPv4 !Word32
    | SocksHostIPv6 !Word32 !Word32 !Word32 !Word32
    | SocksHostName ByteString
    deriving (Show, Eq)

type SocksPort = Word16

data SocksReplyFailure =
      SocksReplyFailureGeneralServerFailure
    | SocksReplyFailureConnectionNotAllowedByRuleSet
    | SocksReplyFailureNetworkUnreachable
    | SocksReplyFailureHostUnreachable
    | SocksReplyFailureConnectionRefused
    | SocksReplyFailureTTLExpired
    | SocksReplyFailureCommandNotSupported
    | SocksReplyFailureAddrTypeNotSupported
    | SocksReplyFailureOther !Word8 -- 0x09 <= x <= 0xFF
    deriving (Show, Eq)

type SocksUdpFragmentNumber = Word8


-- Messages

newtype SocksMethodRequest = SocksMethodRequest [SocksMethod]
    deriving (Show, Eq)

newtype SocksMethodResponse = SocksMethodResponse (Maybe SocksMethod)
    deriving (Show, Eq)

newtype SocksUsernamePasswordRequest = SocksUsernamePasswordRequest SocksUsernamePassword
    deriving (Show, Eq)

data SocksUsernamePasswordResponse =
      SocksUsernamePasswordResponseSuccess
    | SocksUsernamePasswordResponseFailure Word8
    deriving (Show, Eq)

data SocksRequest = SocksRequest
    { socksCommand :: SocksCommand
    , socksEndpoint :: SocksEndpoint
    } deriving (Show, Eq)

data SocksResponse =
      SocksResponseSuccess SocksEndpoint
    | SocksResponseFailure SocksReplyFailure
    deriving (Show, Eq)

data SocksUdpRequest = SocksUdpRequest
    { socksUdpFragmentNumber :: SocksUdpFragmentNumber
    , socksUdpEndpoint :: SocksEndpoint
    , socksUdpData :: ByteString
    } deriving (Show, Eq)


-- Serialization

instance Serialize SocksMethodRequest where
    put (SocksMethodRequest methods) = do
        putSocksVersion
        putlengthPrefixedList (putWord8 . socksMethodAsByte) methods
    get = do
        getSocksVersion
        methodBytes <- getlengthPrefixedList getWord8
        case sequenceA (map byteAsMaybeSocksMethod methodBytes) of
            Just methods -> return (SocksMethodRequest methods)
            Nothing -> fail "[SocksMethodRequest] invalid NO_ACCEPTABLE_METHODS in socks method request"

instance Serialize SocksMethodResponse where
    put (SocksMethodResponse mmeth) = do
        putSocksVersion
        putWord8 (maybe 0xff socksMethodAsByte mmeth)
    get = do
        getSocksVersion
        SocksMethodResponse . byteAsMaybeSocksMethod <$> getWord8

instance Serialize SocksUsernamePasswordRequest where
    put (SocksUsernamePasswordRequest (SocksUsernamePassword user pass)) = do
        putSocksUsernamePasswordVersion
        putLengthPrefixedByteString user
        putLengthPrefixedByteString pass
    get = do
        getSocksUsernamePasswordVersion
        SocksUsernamePasswordRequest <$>
            (SocksUsernamePassword <$> getLengthPrefixedByteString <*> getLengthPrefixedByteString)

instance Serialize SocksUsernamePasswordResponse where
    put resp = do
        putSocksUsernamePasswordVersion
        putWord8 $ case resp of
            SocksUsernamePasswordResponseSuccess -> 0
            SocksUsernamePasswordResponseFailure s -> s
    get = do
        getSocksUsernamePasswordVersion
        n <- getWord8
        return $ case n of
            0 -> SocksUsernamePasswordResponseSuccess
            _ -> SocksUsernamePasswordResponseFailure n

instance Serialize SocksRequest where
    put (SocksRequest command endpoint) = do
        putSocksVersion
        putWord8 $ case command of
            SocksCommandConnect -> 1
            SocksCommandBind -> 2
            SocksCommandUdpAssociate -> 3
        putWord8 0
        putSocksEndpoint endpoint
    get = do
        getSocksVersion
        w <- getWord8
        command <- case w of
            1 -> return SocksCommandConnect
            2 -> return SocksCommandBind
            3 -> return SocksCommandUdpAssociate
            _ -> fail $ "[SocksRequest] invalid socks command: " ++ show w
        getElse 0 $ const "[SocksRequest] incorrect RSV value"
        SocksRequest command <$> getSocksEndpoint

instance Serialize SocksResponse where
    put resp = do
        putSocksVersion
        case resp of
            SocksResponseSuccess endpoint -> do
                putWord8 0
                putWord8 0
                putSocksEndpoint endpoint
            SocksResponseFailure failure -> do
                putWord8 (socksReplyFailureAsByte failure)
                putWord8 0
                putSocksEndpoint (SocksEndpoint (SocksHostName mempty) 0)
    get = do
        getSocksVersion
        reply <- getWord8
        getElse 0 $ const "[SocksResponse] incorrect RSV value"
        endpoint <- getSocksEndpoint
        return . maybe (SocksResponseSuccess endpoint) SocksResponseFailure $
            byteAsMaybeSocksReplyFailure reply

instance Serialize SocksUdpRequest where
    put _ = do
        error "Serialize SocksUdpRequest: not yet implemented"
    get = do
        error "Serialize SocksUdpRequest: not yet implemented"


getElse :: Word8 -> (Word8 -> String) -> Get()
getElse w msg = do
    w' <- getWord8
    when (w' /= w) $ fail (msg w')

putlengthPrefixedList :: Putter a -> Putter [a]
putlengthPrefixedList f as = do
    putWord8 (fromIntegral (length as))
    traverse_ f as

getlengthPrefixedList :: Get a -> Get [a]
getlengthPrefixedList f = do
    n <- getWord8
    replicateM (fromEnum n) f

putLengthPrefixedByteString :: Putter ByteString
putLengthPrefixedByteString bs = do
    putWord8 (fromIntegral (B.length bs))
    putByteString bs

getLengthPrefixedByteString :: Get ByteString
getLengthPrefixedByteString = getWord8 >>= getBytes . fromIntegral

putSocksEndpoint :: Putter SocksEndpoint
putSocksEndpoint (SocksEndpoint host port) = do
    case host of
        SocksHostIPv4 a -> do
            putWord8 1
            putWord32be a
        SocksHostIPv6 a b c d -> do
            putWord8 4
            putWord32be a
            putWord32be b
            putWord32be c
            putWord32be d
        SocksHostName name -> do
            putWord8 3
            putLengthPrefixedByteString name
    putWord16be port

getSocksEndpoint :: Get SocksEndpoint
getSocksEndpoint = do
    atyp <- getWord8
    endpoint <- case atyp of
        1 -> SocksHostIPv4 <$> getWord32host
        4 -> SocksHostIPv6 <$> getWord32host <*> getWord32host <*> getWord32host <*> getWord32host
        3 -> SocksHostName <$> getLengthPrefixedByteString
        _ -> fail $ "invalid ATYP in endpoint: " ++ show atyp
    SocksEndpoint endpoint <$> getWord16be

putSocksVersion :: Put
putSocksVersion = putWord8 5

getSocksVersion :: Get ()
getSocksVersion = getElse 5 $ \v ->
    "invalid socks version: " ++ show v

putSocksUsernamePasswordVersion :: Put
putSocksUsernamePasswordVersion = putWord8 1

getSocksUsernamePasswordVersion :: Get ()
getSocksUsernamePasswordVersion = getElse 1 $ \v ->
    "invalid socks username/password version: " ++ show v

socksMethodAsByte :: SocksMethod -> Word8
socksMethodAsByte SocksMethodNone = 0
socksMethodAsByte SocksMethodGSSAPI = 1
socksMethodAsByte SocksMethodUsernamePassword = 2
socksMethodAsByte (SocksMethodOther w) = w

byteAsMaybeSocksMethod :: Word8 -> Maybe SocksMethod
byteAsMaybeSocksMethod 0xff = Nothing
byteAsMaybeSocksMethod 0 = Just SocksMethodNone
byteAsMaybeSocksMethod 1 = Just SocksMethodGSSAPI
byteAsMaybeSocksMethod 2 = Just SocksMethodUsernamePassword
byteAsMaybeSocksMethod w = Just (SocksMethodOther w)

socksReplyFailureAsByte :: SocksReplyFailure -> Word8
socksReplyFailureAsByte SocksReplyFailureGeneralServerFailure = 1
socksReplyFailureAsByte SocksReplyFailureConnectionNotAllowedByRuleSet = 2
socksReplyFailureAsByte SocksReplyFailureNetworkUnreachable = 3
socksReplyFailureAsByte SocksReplyFailureHostUnreachable = 4
socksReplyFailureAsByte SocksReplyFailureConnectionRefused = 5
socksReplyFailureAsByte SocksReplyFailureTTLExpired = 6
socksReplyFailureAsByte SocksReplyFailureCommandNotSupported = 7
socksReplyFailureAsByte SocksReplyFailureAddrTypeNotSupported = 8
socksReplyFailureAsByte (SocksReplyFailureOther w) = w

byteAsMaybeSocksReplyFailure :: Word8 -> Maybe SocksReplyFailure
byteAsMaybeSocksReplyFailure 0 = Nothing
byteAsMaybeSocksReplyFailure 1 = Just SocksReplyFailureGeneralServerFailure
byteAsMaybeSocksReplyFailure 2 = Just SocksReplyFailureConnectionNotAllowedByRuleSet
byteAsMaybeSocksReplyFailure 3 = Just SocksReplyFailureNetworkUnreachable
byteAsMaybeSocksReplyFailure 4 = Just SocksReplyFailureHostUnreachable
byteAsMaybeSocksReplyFailure 5 = Just SocksReplyFailureConnectionRefused
byteAsMaybeSocksReplyFailure 6 = Just SocksReplyFailureTTLExpired
byteAsMaybeSocksReplyFailure 7 = Just SocksReplyFailureCommandNotSupported
byteAsMaybeSocksReplyFailure 8 = Just SocksReplyFailureAddrTypeNotSupported
byteAsMaybeSocksReplyFailure w = Just (SocksReplyFailureOther w)

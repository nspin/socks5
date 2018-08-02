{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeFamilies #-}

module Network.Socks5.Flow
    (
      SocksException(..)
    , SocksContext(..)

    , socksClientJustSelectMethod
    , socksServerJustSelectMethod
    , socksClientJustAuthenticateWithUsernamePassword
    , socksServerJustAuthenticateWithUsernamePassword
    , socksClientJustCommand
    , socksServerSuccess
    , socksServerFailure

    , socksClientCommand
    , socksClientConnect
    , socksClientAuthenticate
    , SocksClientAuthenticationPreference(..)

    , socksServerAuthenticate
    , socksServerAuthenticateConnect
    , SocksServerUsernamePasswordGuard
    , SocksAuthenticationPreference(..)
    , SocksAuthenticationPreferenceNone(..)
    , SocksAuthenticationPreferenceUsernamePassword(..)
    , SocksAuthenticationPreferenceNoneOrUsernamePassword(..)
    , SocksAuthenticationPreferenceUsernamePasswordOrNone(..)

    ) where

import Control.Exception (Exception)
import Control.Monad (void)
import Data.ByteString (ByteString)
import Data.Serialize
import Data.Word (Word8)
import Network.Socks5.Types


data SocksException =
      SocksProtocolException String -- ^ deserialization failure
    | SocksNoAcceptibleMethodsException
    | SocksUsernamePasswordAuthenticationFailureException Word8
    | SocksReplyFailureException SocksReplyFailure
    deriving (Show, Eq)

instance Exception SocksException

-- TODO: Improve this interface
data SocksContext m = SocksContext
    { socksContextSend :: ByteString -> m ()
    , socksContextRecv :: forall r. Get r -> m (Either String r)
    , socksContextThrow :: forall a. SocksException -> m a
    }

socksSend :: Serialize a => SocksContext m -> a -> m ()
socksSend ctx a = socksContextSend ctx . runPut $ put a

socksRecv :: (Monad m, Serialize a) => SocksContext m -> m a
socksRecv ctx = (socksContextRecv ctx) get >>= either (socksContextThrow ctx . SocksProtocolException) return

socksThrow :: SocksContext m -> SocksException -> m a
socksThrow = socksContextThrow


socksClientJustSelectMethod :: Monad m => SocksContext m -> [SocksMethod] -> m SocksMethod
socksClientJustSelectMethod ctx methods = do
    socksSend ctx $ SocksMethodRequest methods
    SocksMethodResponse mmethod <- socksRecv ctx
    case mmethod of
        Nothing -> socksThrow ctx SocksNoAcceptibleMethodsException
        Just method ->
            if method `elem` methods
            then return method
            else socksThrow ctx SocksNoAcceptibleMethodsException

socksServerJustSelectMethod :: Monad m => SocksContext m -> [SocksMethod] -> m SocksMethod
socksServerJustSelectMethod ctx preferredMethods = do
    SocksMethodRequest clientMethods <- socksRecv ctx
    case filter (`elem` preferredMethods) clientMethods of
        [] -> do
            socksSend ctx $ SocksMethodResponse Nothing
            socksThrow ctx SocksNoAcceptibleMethodsException
        (method:_) -> do
            socksSend ctx $ SocksMethodResponse (Just method)
            return method

socksClientJustAuthenticateWithUsernamePassword :: Monad m => SocksContext m -> SocksUsernamePassword -> m ()
socksClientJustAuthenticateWithUsernamePassword ctx creds = do
    socksSend ctx $ SocksUsernamePasswordRequest creds
    resp <- socksRecv ctx
    case resp of
        SocksUsernamePasswordResponseSuccess -> return ()
        SocksUsernamePasswordResponseFailure w -> socksThrow ctx $ SocksUsernamePasswordAuthenticationFailureException w

socksServerJustAuthenticateWithUsernamePassword :: Monad m => SocksContext m -> SocksServerUsernamePasswordGuard m a -> m a
socksServerJustAuthenticateWithUsernamePassword ctx guard = do
    SocksUsernamePasswordRequest creds <- socksRecv ctx
    r <- guard creds
    case r of
        Right a -> a <$ socksSend ctx SocksUsernamePasswordResponseSuccess
        Left w -> do
            socksSend ctx $ SocksUsernamePasswordResponseFailure w
            socksThrow ctx $ SocksUsernamePasswordAuthenticationFailureException w

socksClientJustCommand :: Monad m
                       => SocksContext m
                       -> SocksCommand
                       -> SocksEndpoint
                       -> m SocksEndpoint
socksClientJustCommand ctx command endpoint = do
    socksSend ctx $ SocksRequest command endpoint
    resp <- socksRecv ctx
    case resp of
        SocksResponseSuccess bound -> return bound
        SocksResponseFailure failure -> socksThrow ctx $ SocksReplyFailureException failure

socksServerSuccess :: Monad m => SocksContext m -> SocksEndpoint -> m ()
socksServerSuccess ctx endpoint = socksSend ctx $ SocksResponseSuccess endpoint

socksServerFailure :: Monad m => SocksContext m -> SocksReplyFailure -> m a
socksServerFailure ctx failure = do
    socksSend ctx $ SocksResponseFailure failure
    socksThrow ctx $ SocksReplyFailureException failure


socksClientAuthenticate :: Monad m => SocksContext m -> SocksClientAuthenticationPreference -> m ()
socksClientAuthenticate ctx pref = case pref of
    SocksClientAuthenticationPreferenceNone ->
        void $ socksClientJustSelectMethod ctx [SocksMethodNone]
    SocksClientAuthenticationPreferenceUsernamePassword creds ->
        go creds [SocksMethodUsernamePassword]
    SocksClientAuthenticationPreferenceNoneOrUsernamePassword creds ->
        go creds [SocksMethodNone, SocksMethodUsernamePassword]
    SocksClientAuthenticationPreferenceUsernamePasswordOrNone creds ->
        go creds [SocksMethodUsernamePassword, SocksMethodNone]
  where
    go creds methods = do
        method <- socksClientJustSelectMethod ctx methods
        case method of
            SocksMethodNone -> return ()
            SocksMethodUsernamePassword -> socksClientJustAuthenticateWithUsernamePassword ctx creds

socksClientCommand :: Monad m
                   => SocksContext m
                   -> SocksClientAuthenticationPreference
                   -> SocksCommand
                   -> SocksEndpoint
                   -> m SocksEndpoint
socksClientCommand ctx pref command endpoint = do
    socksClientAuthenticate ctx pref
    socksClientJustCommand ctx command endpoint

socksClientConnect :: Monad m => SocksContext m -> SocksClientAuthenticationPreference -> SocksEndpoint -> m SocksEndpoint
socksClientConnect ctx pref = socksClientCommand ctx pref SocksCommandConnect

data SocksClientAuthenticationPreference =
      SocksClientAuthenticationPreferenceNone
    | SocksClientAuthenticationPreferenceUsernamePassword SocksUsernamePassword
    | SocksClientAuthenticationPreferenceNoneOrUsernamePassword SocksUsernamePassword
    | SocksClientAuthenticationPreferenceUsernamePasswordOrNone SocksUsernamePassword
    deriving (Show, Eq)


socksServerAuthenticate :: (Monad m, SocksAuthenticationPreference pref)
                        => SocksContext m
                        -> pref m
                        -> m (SocksServerAuthenticationResult pref, SocksRequest)
socksServerAuthenticate ctx pref = (,)
    <$> socksServerAuthenticate' ctx pref
    <*> socksRecv ctx

socksServerAuthenticateConnect :: (Monad m, SocksAuthenticationPreference pref)
                               => SocksContext m
                               -> pref m
                               -> m (SocksServerAuthenticationResult pref, SocksEndpoint)
socksServerAuthenticateConnect ctx pref = do
    (r, req) <- socksServerAuthenticate ctx pref
    case req of
        SocksRequest SocksCommandConnect endpoint -> return (r, endpoint)
        SocksRequest _ _ -> do
            socksSend ctx (SocksResponseFailure SocksReplyFailureCommandNotSupported)
            socksThrow ctx (SocksReplyFailureException SocksReplyFailureCommandNotSupported)


-- TODO: Include information about the client connection, provided through SocksContext.
type SocksServerUsernamePasswordGuard m r = SocksUsernamePassword -> m (Either Word8 r)

data SocksAuthenticationPreferenceNone (m :: * -> *) = SocksAuthenticationPreferenceNone
data SocksAuthenticationPreferenceUsernamePassword r m = SocksAuthenticationPreferenceUsernamePassword (SocksServerUsernamePasswordGuard m r)
data SocksAuthenticationPreferenceNoneOrUsernamePassword r m = SocksAuthenticationPreferenceNoneOrUsernamePassword (SocksServerUsernamePasswordGuard m r)
data SocksAuthenticationPreferenceUsernamePasswordOrNone r m = SocksAuthenticationPreferenceUsernamePasswordOrNone (SocksServerUsernamePasswordGuard m r)

class SocksAuthenticationPreference (pref :: (* -> *) -> *) where
    type SocksServerAuthenticationResult pref :: *
    mapAuthenticationPreference :: (forall a. m a -> n a) -> pref m -> pref n
    socksServerAuthenticate' :: Monad m => SocksContext m -> pref m -> m (SocksServerAuthenticationResult pref)

instance SocksAuthenticationPreference SocksAuthenticationPreferenceNone where
    type SocksServerAuthenticationResult SocksAuthenticationPreferenceNone = ()
    mapAuthenticationPreference _ _ = SocksAuthenticationPreferenceNone
    socksServerAuthenticate' ctx _ = void $ socksServerJustSelectMethod ctx [SocksMethodNone]

instance SocksAuthenticationPreference (SocksAuthenticationPreferenceUsernamePassword r) where
    type SocksServerAuthenticationResult (SocksAuthenticationPreferenceUsernamePassword r) = r
    mapAuthenticationPreference f (SocksAuthenticationPreferenceUsernamePassword m) = SocksAuthenticationPreferenceUsernamePassword (f . m)
    socksServerAuthenticate' ctx (SocksAuthenticationPreferenceUsernamePassword guard) = do
        socksServerJustSelectMethod ctx [SocksMethodUsernamePassword]
        socksServerJustAuthenticateWithUsernamePassword ctx guard

instance SocksAuthenticationPreference (SocksAuthenticationPreferenceNoneOrUsernamePassword r) where
    type SocksServerAuthenticationResult (SocksAuthenticationPreferenceNoneOrUsernamePassword r) = Maybe r
    mapAuthenticationPreference f (SocksAuthenticationPreferenceNoneOrUsernamePassword m) = SocksAuthenticationPreferenceNoneOrUsernamePassword (f . m)
    socksServerAuthenticate' ctx (SocksAuthenticationPreferenceNoneOrUsernamePassword guard) = socksServerAuthenticateAny ctx guard [SocksMethodNone, SocksMethodUsernamePassword]

instance SocksAuthenticationPreference (SocksAuthenticationPreferenceUsernamePasswordOrNone r) where
    type SocksServerAuthenticationResult (SocksAuthenticationPreferenceUsernamePasswordOrNone r) = Maybe r
    mapAuthenticationPreference f (SocksAuthenticationPreferenceUsernamePasswordOrNone m) = SocksAuthenticationPreferenceUsernamePasswordOrNone (f . m)
    socksServerAuthenticate' ctx (SocksAuthenticationPreferenceUsernamePasswordOrNone guard) = socksServerAuthenticateAny ctx guard [SocksMethodUsernamePassword, SocksMethodNone]

socksServerAuthenticateAny :: Monad m => SocksContext m -> SocksServerUsernamePasswordGuard m r -> [SocksMethod] -> m (Maybe r)
socksServerAuthenticateAny ctx guard methods = do
    method <- socksServerJustSelectMethod ctx methods
    case method of
        SocksMethodNone -> return Nothing
        SocksMethodUsernamePassword -> Just <$> socksServerJustAuthenticateWithUsernamePassword ctx guard

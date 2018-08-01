module Data.Conduit.Serialize
  ( sinkGet
  ) where

import Data.ByteString (ByteString)
import Data.Conduit (ConduitT, await, leftover)
import Data.Maybe (fromMaybe)
import Data.Serialize

sinkGet :: Monad m => Get r -> ConduitT ByteString o m (Either String r)
sinkGet = go . runGetPartial
  where
    go parse = do
        mchunk <- await
        case parse (fromMaybe mempty mchunk) of
            Done r   rest  -> Right r   <$ leftover rest 
            Fail msg rest  -> Left  msg <$ leftover rest 
            Partial parse' -> go parse' -- not possible if mchunk was Nothing

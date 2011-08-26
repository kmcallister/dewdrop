module Dewdrop
    ( dewdrop
    , usesRegister, usesSegment, opcode
    , module Hdis86
    ) where

import Dewdrop.Analyze

import System.Environment
import Control.Monad
import Control.Applicative
import Control.Exception ( throwIO, ErrorCall(..) )

import Data.Typeable ( Typeable )
import Data.Data     ( Data )

import qualified Data.ByteString as B
import qualified Generics.SYB    as G

import Data.Elf
import Hdis86

dewdrop :: ([Metadata] -> Bool) -> IO ()
dewdrop wanted = do
    args@(~(elf_file:_)) <- getArgs
    when (null args) $ do
        progname <- getProgName
        throwIO $ ErrorCall ("Usage: " ++ progname ++ " ELF-FILE")
    elf <- parseElf <$> B.readFile elf_file
    mapM_ print . filter (\g@(Gadget xs) -> valid g && wanted xs) . gadgets $ elf

hasSub :: (Typeable a, Eq a, Data b) => a -> b -> Bool
hasSub x = not . null . G.listify (== x)

usesRegister :: GPR -> Metadata -> Bool
usesRegister = hasSub

usesSegment :: Segment -> Metadata -> Bool
usesSegment = hasSub

opcode :: Metadata -> Opcode
opcode = inOpcode . mdInst

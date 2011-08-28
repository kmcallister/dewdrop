{- | Print ROP gadgets having some desired property.

This module provides the quickest way to get started:

> $ cat find.hs
>
> import Dewdrop
> main = dewdrop (any (usesRegister RBP))
>
> $ runhaskell find.hs /bin/ls
> 00402e56:
>   pop %rbp
>   ret
>
> 0040afe7:
>   shl %cl, -0x15(%rbp)
>   rep ret
>
> ...

If you need more control, see "Dewdrop.Analyze".

-}

module Dewdrop
    ( -- * Finding gadgets
      dewdrop

      -- * Helpers for selecting gadgets
    , usesRegister, usesSegment, opcode

      -- * Re-export of disassembler
      --
      -- | The types and functions of @Hdis86@
      -- are re-exported for convenience.
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

-- | Opens the ELF binary file passed as the first command-line
-- argument, and prints all ROP gadgets satisfying the specified
-- property.
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

-- | Does this instruction use a given register?
--
-- This only includes registers explicitly mentioned in disassembly,
-- and not e.g. the @rsi@ / @rdi@ operands of @movsd@.
usesRegister :: GPR -> Metadata -> Bool
usesRegister = hasSub

-- | Does this instruction mention a given segment register?
--
-- This only includes explicit overrides, and loads/stores of
-- segment registers.
usesSegment :: Segment -> Metadata -> Bool
usesSegment = hasSub

-- | Get the @'Opcode'@ directly from an instruction-with-metadata.
opcode :: Metadata -> Opcode
opcode = inOpcode . mdInst

import System.Environment
import Control.Monad
import Control.Applicative
import Numeric
import Data.List

import qualified Generics.SYB    as G
import qualified Data.ByteString as B

import Data.Elf
import Hdis86

type Gadget = [Metadata]

execSections :: Elf -> [ElfSection]
execSections = filter ((SHF_EXECINSTR `elem`) . elfSectionFlags) . elfSections

gadgets :: Elf -> [Gadget]
gadgets = concatMap scanSect . execSections where
    scanSect sect = do
        let bytes = elfSectionData sect
        index <- B.elemIndices 0xC3 $ bytes
        let hd = B.take (index + 1) bytes
            maxCandidate = 20
        subseq <- B.tails $ B.drop (B.length hd - maxCandidate) hd
        let addr =   elfSectionAddr sect
                   + fromIntegral index
                   - fromIntegral (B.length subseq)
            cfg  = amd64 { cfgOrigin = addr
                         , cfgSyntax = SyntaxATT }
        return (disassembleMetadata cfg subseq)

formatOne :: Gadget -> String
formatOne g@(g1:_)
    = showHex (mdOffset g1) $ (":\n" ++) $
      intercalate "\n" $
      map (("  "++) . mdAssembly) g
formatOne [] = error "empty gadget"

wanted :: [Metadata] -> Bool
wanted g = valid (map mdInst g) && all (noStack . mdInst) g && any (usesReg RSI . mdInst) g
    -- Customize this to filter for gadgets that have some property
    -- you want
    where
        valid insns@(_:_:_)
            | any ((== Iinvalid) . inOpcode) insns
                = False
            | otherwise
                = inOpcode (last insns) == Iret
        valid _ = False

        usesReg :: (G.Data a) => GPR -> a -> Bool
        usesReg  r = (not . null) . G.listify (== r)

        noStack  (Inst _ Ipush _) = False
        noStack  (Inst _ Ipop  _) = False
        noStack  (Inst _ _ operands) = all (not . usesReg RSP) operands

main :: IO ()
main =
    do args@(~[elf_file]) <- getArgs
       when (null args) $
           error "Usage: findROP ELF-FILE"
       elf <- parseElf <$> B.readFile elf_file
       let found = filter wanted . gadgets $ elf
       mapM_ (putStrLn . formatOne) found

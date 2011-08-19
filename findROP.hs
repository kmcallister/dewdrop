import System.Environment
import Control.Monad
import Control.Applicative
import Data.Word
import Numeric
import Data.List

import qualified Data.Set as S
import qualified Data.ByteString as B

import Data.Elf
import Hdis86

type Address = Word64

data Candidate = C
    { candidateAddress :: Address
    , candidateBytes   :: B.ByteString
    } deriving (Show)

type Gadget = [Metadata]

toGadget :: Candidate -> Gadget
toGadget (C addr bytes) = disassembleMetadata cfg $ bytes
    where
        cfg = amd64 { cfgOrigin = addr
                    , cfgSyntax = SyntaxATT }

maxCandidate :: Int
maxCandidate = 20

execSections :: Elf -> [ElfSection]
execSections = filter ((SHF_EXECINSTR `elem`) . elfSectionFlags) . elfSections

findROP :: Elf -> [Candidate]
findROP = concatMap (filter valid . candidates) . execSections

valid :: Candidate -> Bool
valid (C _ bytes) =
    case insns of
        []  -> False
        [_] -> False
        _ | any invalid insns -> False
        _ -> case last insns of
                 (Inst _ Iret _) -> True
                 _               -> False

    where
        insns = disassemble amd64 bytes
        invalid (Inst _ Iinvalid _) = True
        invalid _                   = False

candidates :: ElfSection -> [Candidate]
candidates sect =
    do let bytes = elfSectionData sect
       index <- B.elemIndices 0xC3 $ bytes
       let hd = B.take (index + 1) bytes
       sq    <- B.tails $ B.drop (B.length hd - maxCandidate) hd
       return $ C (elfSectionAddr sect +
                   fromIntegral index -
                   (fromIntegral $ B.length sq)) sq

formatOne :: Gadget -> String
formatOne g@(g1:_)
    = showHex (mdOffset g1) $ (":\n" ++) $
      intercalate "\n" $
      map (("  "++) . mdAssembly) g
formatOne [] = error "empty gadget"

dedup :: [Candidate] -> [Candidate]
dedup xs = go xs S.empty
    where
        go [] _ = []
        go (c:cs) seen
            | (candidateAddress c) `S.member` seen = go cs seen
            | otherwise  = c : go cs (S.insert (candidateAddress c) seen)

wanted :: [Metadata] -> Bool
wanted g = all (noStack . mdInst) g && any (rsi . mdInst) g
    -- Customize this to filter for gadgets that have some property
    -- you want
    where
        noStack  (Inst _ Ipush _) = False
        noStack  (Inst _ Ipop  _) = False
        noStack  (Inst _ _ operands) = all (not . usesReg RSP) operands
        usesReg  r (Reg rr)   = usesReg' r rr
        usesReg  r (Mem (Memory _ base index _ _)) = usesReg' r base || usesReg' r index
        usesReg  _ _          = False
        usesReg' r (Reg8  rr _)   = r == rr
        usesReg' r (Reg16 rr)     = r == rr
        usesReg' r (Reg32 rr)     = r == rr
        usesReg' r (Reg64 rr)     = r == rr
        usesReg' _ _              = False
        usesMemReg  r (Mem (Memory _ base index _ _)) = usesReg' r base || usesReg' r index
        usesMemReg  _ _           = False
        rsi (Inst _ _ operands)   = any (usesMemReg RDI) operands

main :: IO ()
main =
    do args@(~[elf_file]) <- getArgs
       when (null args) $
           error "Usage: findROP ELF-FILE"
       elf <- parseElf <$> B.readFile elf_file
       let gadgets = filter wanted . map toGadget . dedup . findROP $ elf
       mapM_ (putStrLn . formatOne) $ gadgets

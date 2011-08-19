import qualified Data.ByteString as B
import System.Environment (getArgs)
import Control.Monad (when)
import Data.Word (Word64)
import Numeric (showHex)
import Data.List (intercalate, sortBy)
import Data.Function (on)
import qualified Data.Set as S

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

maxCandidate = 20

flagSections :: ElfSectionFlags -> Elf -> [ElfSection]
flagSections flag elf = [s | s <- elfSections elf,
                                  elem flag $ elfSectionFlags s]

execSections :: Elf -> [ElfSection]
execSections = flagSections SHF_EXECINSTR

findROP elf = let exec = execSections elf in concatMap findROPOne exec

findROPOne sect = filter valid $ candidates sect

valid :: Candidate -> Bool
valid (C _ bytes) =
    let insns = disassemble amd64 bytes
    in case insns of
           []  -> False
           [_] -> False
           _ | any invalid insns -> False
           _ -> case (last $ insns) of
                    (Inst _ Iret _) -> True
                    _               -> False

    where
        invalid (Inst _ Iinvalid _) = True
        invalid _                   = False

candidates :: ElfSection -> [Candidate]
candidates sect =
    do let bytes = elfSectionData sect
       index <- B.elemIndices 0xC3 $ bytes
       hd    <- return $ B.take (index + 1) bytes
       seq   <- B.tails $ B.drop (B.length hd - maxCandidate) hd
       return $ C (elfSectionAddr sect +
                   fromIntegral index -
                   (fromIntegral $ B.length seq)) seq

formatOne :: Gadget -> String
formatOne g = showHex addr $ (":\n" ++) $
              intercalate "\n" $
              map (("  "++) . mdAssembly) g
    where
        cfg  = amd64 { cfgOrigin = addr
                     , cfgSyntax = SyntaxATT }
        addr = mdOffset $ head g

dedup :: [Candidate] -> [Candidate]
dedup cs = go cs S.empty
    where
        go [] _ = []
        go (c:cs) seen
            | (candidateAddress c) `S.member` seen = go cs seen
            | otherwise  = c : go cs (S.insert (candidateAddress c) seen)

wanted g = all (noStack . mdInst) g && any (rsi . mdInst) g
    -- Customize this to filter for gadgets that have some property
    -- you want
    where
        noStack  (Inst _ Ipush _) = False
        noStack  (Inst _ Ipop  _) = False
        noStack  (Inst _ _ operands) = all (not . usesReg RSP) operands
        usesReg  r (Reg rr)   = usesReg' r rr
        usesReg  r (Mem (Memory _ base index _ _)) = usesReg' r base || usesReg' r index
        usesReg  r _          = False
        usesReg' r (Reg8  rr _)   = r == rr
        usesReg' r (Reg16 rr)     = r == rr
        usesReg' r (Reg32 rr)     = r == rr
        usesReg' r (Reg64 rr)     = r == rr
        usesReg' r _              = False
        usesMemReg  r (Mem (Memory _ base index _ _)) = usesReg' r base || usesReg' r index
        usesMemReg  r _           = False
        rsi (Inst _ _ operands)   = any (usesMemReg RDI) operands

main :: IO ()
main =
    do args <- getArgs
       when (length args < 1) $
            fail "Usage: findROP ELF-FILE"
       contents <- B.readFile $ head args
       elf <- return $ parseElf contents
       gadgets <- return $ filter wanted $ map toGadget $ dedup $ findROP elf
       mapM_ (putStrLn . formatOne) $ gadgets

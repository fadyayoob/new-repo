package ktfunc

// Current-epoch vote visibility. The contract records votes in mappings
// (blockRwd[startBlock][candidate] for tallies, ocRwdrVote[oc][startBlock] for
// who-voted-what) which can't be enumerated directly. We reconstruct them from
// the Voted events of the current epoch, resolving each voter from its tx
// sender, so an operator can see exactly how the epoch stands and tell whether
// it's progressing or wedged.

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	log "github.com/sirupsen/logrus"
)

// resetVoteData is the data string the contract emits on a resetVote (Ktv2.sol
// emits Voted(startBlock, _to, "rst")).
const resetVoteData = "rst"

// epochVote is one operator's current active vote in the epoch.
type epochVote struct {
	Voter     common.Address
	Candidate common.Address
}

// PrintEpochVoteStatus reconstructs and prints, for the current epoch, the
// per-candidate vote tallies and which OC voted for which candidate. Safe to
// call as part of the contract-state printout; it adds a few reads plus a
// Voted-event scan bounded to the current epoch.
func PrintEpochVoteStatus(cProps *ConnectionProps) error {
	callOpts := &bind.CallOpts{Context: context.Background(), From: cProps.MyPubKey}

	startBlock, err := cProps.Kt.StartBlock(callOpts)
	if err != nil {
		return fmt.Errorf("failed to read start block: %w", err)
	}
	interval, err := cProps.Kt.EpochInterval(callOpts)
	if err != nil {
		return fmt.Errorf("failed to read epoch interval: %w", err)
	}
	required, err := cProps.Kt.ConsensusReq(callOpts)
	if err != nil {
		return fmt.Errorf("failed to read consensus requirement: %w", err)
	}
	head, err := cProps.Client.BlockNumber(context.Background())
	if err != nil {
		return fmt.Errorf("failed to read current block: %w", err)
	}

	endBlock := new(big.Int).Add(startBlock, big.NewInt(int64(interval)))

	votes, err := gatherEpochVotes(cProps, startBlock, head)
	if err != nil {
		return err
	}

	log.Printf("Epoch vote status (epoch start %s, ends at block %s, consensusReq %d):",
		startBlock.String(), endBlock.String(), required)
	if head <= endBlock.Uint64() {
		log.Printf("  Epoch is not yet complete (head %d <= end %d). Voting has not opened.", head, endBlock.Uint64())
	}

	if len(votes) == 0 {
		log.Printf("  No votes cast in this epoch yet.")
		return nil
	}

	// Authoritative per-candidate tally straight from the contract, plus the
	// reconstructed who-voted-what.
	tally := make(map[common.Address]uint16)
	candidates := make([]common.Address, 0)
	for _, v := range votes {
		if _, seen := tally[v.Candidate]; !seen {
			count, err := cProps.Kt.BlockRwd(callOpts, startBlock, v.Candidate)
			if err != nil {
				return fmt.Errorf("failed to read tally for %s: %w", v.Candidate.Hex(), err)
			}
			tally[v.Candidate] = count
			candidates = append(candidates, v.Candidate)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return tally[candidates[i]] > tally[candidates[j]] })

	log.Printf("  Candidate tallies:")
	for _, c := range candidates {
		marker := ""
		if tally[c] >= required {
			marker = "  <-- CONSENSUS REACHED"
		}
		log.Printf("    %s: %d/%d%s", c.Hex(), tally[c], required, marker)
	}

	sort.Slice(votes, func(i, j int) bool {
		return strings.ToLower(votes[i].Voter.Hex()) < strings.ToLower(votes[j].Voter.Hex())
	})
	log.Printf("  Votes by node (OC):")
	for _, v := range votes {
		log.Printf("    %s voted for %s", v.Voter.Hex(), v.Candidate.Hex())
	}
	return nil
}

// gatherEpochVotes scans Voted events for the given epoch and returns each OC's
// current active vote (resets net out an earlier vote). Voters are resolved
// from the transaction sender, since the Voted event records the candidate but
// not the voter.
func gatherEpochVotes(cProps *ConnectionProps, startBlock *big.Int, head uint64) ([]epochVote, error) {
	chunkSize := uint64(cProps.ChunkSize)
	if chunkSize == 0 {
		chunkSize = uint64(DefaultChunkSize)
	}

	txSender := make(map[common.Hash]common.Address)
	resolveSender := func(txHash common.Hash) (common.Address, bool) {
		if s, ok := txSender[txHash]; ok {
			return s, s != (common.Address{})
		}
		tx, isPending, err := cProps.Client.TransactionByHash(context.Background(), txHash)
		if err != nil || isPending || tx == nil {
			txSender[txHash] = common.Address{}
			return common.Address{}, false
		}
		sender, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
		if err != nil {
			txSender[txHash] = common.Address{}
			return common.Address{}, false
		}
		txSender[txHash] = sender
		return sender, true
	}

	// Track each OC's latest vote in event order; a reset clears it. seen keeps
	// the display order stable and prevents a re-vote after a reset from listing
	// the same voter twice.
	current := make(map[common.Address]common.Address)
	seen := make(map[common.Address]bool)
	order := make([]common.Address, 0)

	start := startBlock.Uint64()
	for from := start; from <= head; from += chunkSize {
		to := from + chunkSize - 1
		if to > head {
			to = head
		}
		end := to
		iter, err := cProps.Kt.FilterVoted(&bind.FilterOpts{Start: from, End: &end, Context: context.Background()})
		if err != nil {
			return nil, fmt.Errorf("failed to filter Voted events %d-%d: %w", from, to, err)
		}
		for iter.Next() {
			evt := iter.Event()
			if evt == nil || evt.Arg0 == nil || evt.Arg0.Cmp(startBlock) != 0 {
				continue // not this epoch
			}
			voter, ok := resolveSender(evt.Raw.TxHash)
			if !ok {
				continue
			}
			if !seen[voter] {
				seen[voter] = true
				order = append(order, voter)
			}
			if evt.Arg2 == resetVoteData {
				delete(current, voter)
				continue
			}
			current[voter] = evt.Arg1
		}
		if err := iter.Error(); err != nil {
			iter.Close()
			return nil, fmt.Errorf("error iterating Voted events: %w", err)
		}
		iter.Close()
	}

	result := make([]epochVote, 0, len(current))
	for _, voter := range order {
		if c, ok := current[voter]; ok {
			result = append(result, epochVote{Voter: voter, Candidate: c})
		}
	}
	return result, nil
}

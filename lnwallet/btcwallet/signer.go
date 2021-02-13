package btcwallet

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/pine"
	"github.com/lightningnetwork/lnd/pine/serializers"
)

// FetchInputInfo queries for the WalletController's knowledge of the passed
// outpoint. If the base wallet determines this output is under its control,
// then the original txout should be returned. Otherwise, a non-nil error value
// of ErrNotMine should be returned instead.
//
// This is a part of the WalletController interface.
func (b *BtcWallet) FetchInputInfo(prevOut *wire.OutPoint) (*lnwallet.Utxo, error) {
	txOut, err := pine.FetchInputInfo(prevOut)
	if err != nil {
		return nil, err
	}

	if txOut == nil {
		return nil, lnwallet.ErrNotMine
	}

	return serializers.DeserializeUtxo(txOut)
}

// deriveFromKeyLoc attempts to derive a private key using a fully specified
// KeyLocator.
func deriveFromKeyLoc(scopedMgr *waddrmgr.ScopedKeyManager,
	addrmgrNs walletdb.ReadWriteBucket,
	keyLoc keychain.KeyLocator) (*btcec.PrivateKey, error) {

	path := waddrmgr.DerivationPath{
		Account: uint32(keyLoc.Family),
		Branch:  0,
		Index:   uint32(keyLoc.Index),
	}
	addr, err := scopedMgr.DeriveFromKeyPath(addrmgrNs, path)
	if err != nil {
		return nil, err
	}

	return addr.(waddrmgr.ManagedPubKeyAddress).PrivKey()
}

// deriveKeyByLocator attempts to derive a key stored in the wallet given a
// valid key locator.
func (b *BtcWallet) deriveKeyByLocator(keyLoc keychain.KeyLocator) (*btcec.PrivateKey, error) {
	// We'll assume the special lightning key scope in this case.
	scopedMgr, err := b.wallet.Manager.FetchScopedKeyManager(
		b.chainKeyScope,
	)
	if err != nil {
		return nil, err
	}

	var key *btcec.PrivateKey
	err = walletdb.Update(b.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		key, err = deriveFromKeyLoc(scopedMgr, addrmgrNs, keyLoc)
		if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
			// If we've reached this point, then the account
			// doesn't yet exist, so we'll create it now to ensure
			// we can sign.
			acctErr := scopedMgr.NewRawAccount(
				addrmgrNs, uint32(keyLoc.Family),
			)
			if acctErr != nil {
				return acctErr
			}

			// Now that we know the account exists, we'll attempt
			// to re-derive the private key.
			key, err = deriveFromKeyLoc(
				scopedMgr, addrmgrNs, keyLoc,
			)
			if err != nil {
				return err
			}
		}

		return err
	})
	if err != nil {
		return nil, err
	}

	return key, nil
}

// fetchPrivKey attempts to retrieve the raw private key corresponding to the
// passed public key if populated, or the key descriptor path (if non-empty).
func (b *BtcWallet) fetchPrivKey(keyDesc *keychain.KeyDescriptor) (*btcec.PrivateKey, error) {
	// If the key locator within the descriptor *isn't* empty, then we can
	// directly derive the keys raw.
	emptyLocator := keyDesc.KeyLocator.IsEmpty()
	if !emptyLocator {
		return b.deriveKeyByLocator(keyDesc.KeyLocator)
	}

	hash160 := btcutil.Hash160(keyDesc.PubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(hash160, b.netParams)
	if err != nil {
		return nil, err
	}

	// Otherwise, we'll attempt to derive the key based on the address.
	// This will only work if we've already derived this address in the
	// past, since the wallet relies on a mapping of addr -> key.
	key, err := b.wallet.PrivKeyForAddress(addr)
	switch {
	// If we didn't find this key in the wallet, then there's a chance that
	// this is actually an "empty" key locator. The legacy KeyLocator
	// format failed to properly distinguish an empty key locator from the
	// very first in the index (0, 0).IsEmpty() == true.
	case waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) && emptyLocator:
		return b.deriveKeyByLocator(keyDesc.KeyLocator)

	case err != nil:
		return nil, err

	default:
		return key, nil
	}
}

// maybeTweakPrivKey examines the single and double tweak parameters on the
// passed sign descriptor and may perform a mapping on the passed private key
// in order to utilize the tweaks, if populated.
func maybeTweakPrivKey(signDesc *input.SignDescriptor,
	privKey *btcec.PrivateKey) (*btcec.PrivateKey, error) {

	var retPriv *btcec.PrivateKey
	switch {

	case signDesc.SingleTweak != nil:
		retPriv = input.TweakPrivKey(privKey,
			signDesc.SingleTweak)

	case signDesc.DoubleTweak != nil:
		retPriv = input.DeriveRevocationPrivKey(privKey,
			signDesc.DoubleTweak)

	default:
		retPriv = privKey
	}

	return retPriv, nil
}

// SignOutputRaw generates a signature for the passed transaction according to
// the data within the passed SignDescriptor.
//
// This is a part of the WalletController interface.
func (b *BtcWallet) SignOutputRaw(tx *wire.MsgTx,
	signDesc *input.SignDescriptor) (input.Signature, error) {

	sig, err := pine.SignOutputRaw(
		serializers.SerializeMsgTx(tx),
		serializers.SerializeSignDescriptor(signDesc),
	)
	if err != nil {
		return nil, err
	}

	return btcec.ParseDERSignature(sig, btcec.S256())
}

// ComputeInputScript generates a complete InputScript for the passed
// transaction with the signature as defined within the passed SignDescriptor.
// This method is capable of generating the proper input script for both
// regular p2wkh output and p2wkh outputs nested within a regular p2sh output.
//
// This is a part of the WalletController interface.
func (b *BtcWallet) ComputeInputScript(tx *wire.MsgTx,
	signDesc *input.SignDescriptor) (*input.Script, error) {

	computeInputScriptResponse, err := pine.ComputeInputScript(
		serializers.SerializeMsgTx(tx),
		serializers.SerializeSignDescriptor(signDesc),
	)
	if err != nil {
		return nil, err
	}

	return &input.Script{
		Witness:   computeInputScriptResponse.Witness,
		SigScript: computeInputScriptResponse.SignatureScript,
	}, nil
}

// A compile time check to ensure that BtcWallet implements the Signer
// interface.
var _ input.Signer = (*BtcWallet)(nil)

// SignMessage attempts to sign a target message with the private key that
// corresponds to the passed public key. If the target private key is unable to
// be found, then an error will be returned. The actual digest signed is the
// double SHA-256 of the passed message.
//
// NOTE: This is a part of the MessageSigner interface.
func (b *BtcWallet) SignMessage(pubKey *btcec.PublicKey,
	msg []byte) (input.Signature, error) {
	return pine.SignMessage(pubKey, msg)
}

// A compile time check to ensure that BtcWallet implements the MessageSigner
// interface.
var _ lnwallet.MessageSigner = (*BtcWallet)(nil)

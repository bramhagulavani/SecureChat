import { describe, it, expect } from 'vitest';
import {
  generateDHKeyPair,
  MAX_SKIP_PER_CHAIN_STEP,
} from '../src/ratchet/ratchetState';
import {
  initializeRatchetAsInitiator,
  initializeRatchetAsResponder,
  ratchetEncrypt,
  ratchetDecrypt,
} from '../src/ratchet/doubleRatchet';

describe('Double Ratchet', () => {
  const sharedSecret = new Uint8Array(32).fill(42);

  it('generates matching message keys for the first message', async () => {
    const bobDH = await generateDHKeyPair();
    const aliceState = await initializeRatchetAsInitiator(sharedSecret, bobDH.publicKey);
    const bobState = initializeRatchetAsResponder(sharedSecret, bobDH);

    const { header, messageKey: aliceKey } = await ratchetEncrypt(aliceState);
    const { messageKey: bobKey } = await ratchetDecrypt(bobState, header);

    expect(aliceKey).toEqual(bobKey);
  });

  it('produces distinct message keys for sequential messages (forward secrecy)', async () => {
    const bobDH = await generateDHKeyPair();
    let aliceState = await initializeRatchetAsInitiator(sharedSecret, bobDH.publicKey);

    const res1 = await ratchetEncrypt(aliceState);
    aliceState = res1.state;
    const res2 = await ratchetEncrypt(aliceState);
    aliceState = res2.state;

    expect(res1.messageKey).not.toEqual(res2.messageKey);
    expect(res1.header.messageNumber).toBe(0);
    expect(res2.header.messageNumber).toBe(1);
  });

  it('turns the ratchet when the receiver replies (direction flip)', async () => {
    const bobDH = await generateDHKeyPair();
    let aliceState = await initializeRatchetAsInitiator(sharedSecret, bobDH.publicKey);
    let bobState = initializeRatchetAsResponder(sharedSecret, bobDH);

    // Alice -> Bob
    const a1 = await ratchetEncrypt(aliceState);
    aliceState = a1.state;
    const b1 = await ratchetDecrypt(bobState, a1.header);
    bobState = b1.state;
    expect(a1.messageKey).toEqual(b1.messageKey);

    // Bob -> Alice (Bob turns sending ratchet)
    const b2 = await ratchetEncrypt(bobState);
    bobState = b2.state;
    const a2 = await ratchetDecrypt(aliceState, b2.header);
    aliceState = a2.state;
    expect(b2.messageKey).toEqual(a2.messageKey);
  });

  it('stays in sync across multiple back-and-forth turns', async () => {
    const bobDH = await generateDHKeyPair();
    let aliceState = await initializeRatchetAsInitiator(sharedSecret, bobDH.publicKey);
    let bobState = initializeRatchetAsResponder(sharedSecret, bobDH);

    for (let turn = 0; turn < 5; turn++) {
      // Alice sends 2 messages
      const a1 = await ratchetEncrypt(aliceState);
      aliceState = a1.state;
      const b1 = await ratchetDecrypt(bobState, a1.header);
      bobState = b1.state;
      expect(a1.messageKey).toEqual(b1.messageKey);

      const a2 = await ratchetEncrypt(aliceState);
      aliceState = a2.state;
      const b2 = await ratchetDecrypt(bobState, a2.header);
      bobState = b2.state;
      expect(a2.messageKey).toEqual(b2.messageKey);

      // Bob sends 1 message
      const b3 = await ratchetEncrypt(bobState);
      bobState = b3.state;
      const a3 = await ratchetDecrypt(aliceState, b3.header);
      aliceState = a3.state;
      expect(b3.messageKey).toEqual(a3.messageKey);
    }
  });

  it('heals after a simulated chain-key leak on next DH turn (post-compromise security)', async () => {
    const bobDH = await generateDHKeyPair();
    let aliceState = await initializeRatchetAsInitiator(sharedSecret, bobDH.publicKey);
    let bobState = initializeRatchetAsResponder(sharedSecret, bobDH);

    // Alice sends msg 1
    const a1 = await ratchetEncrypt(aliceState);
    aliceState = a1.state;
    const b1 = await ratchetDecrypt(bobState, a1.header);
    bobState = b1.state;

    // Suppose attacker got sendingChainKey here
    const compromisedChainKey = aliceState.sendingChainKey;
    expect(compromisedChainKey).not.toBeNull();

    // Bob replies -> turns the DH ratchet
    const b2 = await ratchetEncrypt(bobState);
    bobState = b2.state;
    const a2 = await ratchetDecrypt(aliceState, b2.header);
    aliceState = a2.state;

    // Alice replies -> new sending chain key derived from fresh DH output
    const a3 = await ratchetEncrypt(aliceState);
    aliceState = a3.state;
    const b3 = await ratchetDecrypt(bobState, a3.header);
    bobState = b3.state;

    expect(a3.messageKey).toEqual(b3.messageKey);
    // Attacker cannot derive a3's messageKey from compromisedChainKey
    expect(aliceState.sendingChainKey).not.toEqual(compromisedChainKey);
  });

  it('handles out-of-order messages arriving ahead of expected', async () => {
    const bobDH = await generateDHKeyPair();
    let aliceState = await initializeRatchetAsInitiator(sharedSecret, bobDH.publicKey);
    let bobState = initializeRatchetAsResponder(sharedSecret, bobDH);

    // Alice prepares 3 messages (0, 1, 2)
    const m0 = await ratchetEncrypt(aliceState);
    aliceState = m0.state;
    const m1 = await ratchetEncrypt(aliceState);
    aliceState = m1.state;
    const m2 = await ratchetEncrypt(aliceState);
    aliceState = m2.state;

    // Bob receives message 2 first (skipping 0 and 1)
    const r2 = await ratchetDecrypt(bobState, m2.header);
    bobState = r2.state;

    expect(r2.messageKey).toEqual(m2.messageKey);
    expect(bobState.skippedMessageKeys.size).toBe(2);
  });

  it('decrypts skipped messages when they arrive late', async () => {
    const bobDH = await generateDHKeyPair();
    let aliceState = await initializeRatchetAsInitiator(sharedSecret, bobDH.publicKey);
    let bobState = initializeRatchetAsResponder(sharedSecret, bobDH);

    const m0 = await ratchetEncrypt(aliceState);
    aliceState = m0.state;
    const m1 = await ratchetEncrypt(aliceState);
    aliceState = m1.state;
    const m2 = await ratchetEncrypt(aliceState);
    aliceState = m2.state;

    // Bob receives m2 first
    const r2 = await ratchetDecrypt(bobState, m2.header);
    bobState = r2.state;
    expect(r2.messageKey).toEqual(m2.messageKey);

    // Bob receives m0 late
    const r0 = await ratchetDecrypt(bobState, m0.header);
    bobState = r0.state;
    expect(r0.messageKey).toEqual(m0.messageKey);
    expect(bobState.skippedMessageKeys.size).toBe(1);

    // Bob receives m1 late
    const r1 = await ratchetDecrypt(bobState, m1.header);
    bobState = r1.state;
    expect(r1.messageKey).toEqual(m1.messageKey);
    expect(bobState.skippedMessageKeys.size).toBe(0);
  });

  it('handles skipped messages across a DH ratchet step', async () => {
    const bobDH = await generateDHKeyPair();
    let aliceState = await initializeRatchetAsInitiator(sharedSecret, bobDH.publicKey);
    let bobState = initializeRatchetAsResponder(sharedSecret, bobDH);

    // Alice sends m0 and m1
    const a0 = await ratchetEncrypt(aliceState);
    aliceState = a0.state;
    const a1 = await ratchetEncrypt(aliceState);
    aliceState = a1.state;

    // Bob only receives a0
    const b0 = await ratchetDecrypt(bobState, a0.header);
    bobState = b0.state;

    // Bob sends b0 back to Alice
    const bReply = await ratchetEncrypt(bobState);
    bobState = bReply.state;
    const aReply = await ratchetDecrypt(aliceState, bReply.header);
    aliceState = aReply.state;

    // Alice sends a2 (new DH ratchet step, carrying previousChainLength = 2)
    const a2 = await ratchetEncrypt(aliceState);
    aliceState = a2.state;

    // Bob receives a2 -> should skip and cache a1 from the previous chain!
    const b2 = await ratchetDecrypt(bobState, a2.header);
    bobState = b2.state;
    expect(b2.messageKey).toEqual(a2.messageKey);
    expect(bobState.skippedMessageKeys.size).toBe(1);

    // Now late-arriving a1 is delivered to Bob
    const b1 = await ratchetDecrypt(bobState, a1.header);
    bobState = b1.state;
    expect(b1.messageKey).toEqual(a1.messageKey);
    expect(bobState.skippedMessageKeys.size).toBe(0);
  });

  it('rejects duplicate or replayed messages', async () => {
    const bobDH = await generateDHKeyPair();
    const aliceState = await initializeRatchetAsInitiator(sharedSecret, bobDH.publicKey);
    let bobState = initializeRatchetAsResponder(sharedSecret, bobDH);

    const m0 = await ratchetEncrypt(aliceState);
    const r0 = await ratchetDecrypt(bobState, m0.header);
    bobState = r0.state;

    // Trying to decrypt m0 again without it being in skipped cache
    await expect(ratchetDecrypt(bobState, m0.header)).rejects.toThrow(/duplicate or already-processed/);
  });

  it('rejects an unreasonably large skip count (prevents DoS)', async () => {
    const bobDH = await generateDHKeyPair();
    const aliceState = await initializeRatchetAsInitiator(sharedSecret, bobDH.publicKey);
    const bobState = initializeRatchetAsResponder(sharedSecret, bobDH);

    const { header } = await ratchetEncrypt(aliceState);
    const maliciousHeader = {
      ...header,
      messageNumber: MAX_SKIP_PER_CHAIN_STEP + 10,
    };

    await expect(ratchetDecrypt(bobState, maliciousHeader)).rejects.toThrow(/Too many messages skipped/);
  });
});

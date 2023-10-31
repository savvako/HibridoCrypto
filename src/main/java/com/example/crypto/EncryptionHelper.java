package com.example.crypto;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class EncryptionHelper {
    private static final int BLOCK_SIZE = 16;

    public static byte[] addPadding(byte[] content, int size) {
        byte count = (byte) (size - content.length % size);
        byte[] padded = new byte[content.length + count];
        System.arraycopy(content, 0, padded, 0, content.length);
        for (int i = content.length; i < padded.length; ++i)
            padded[i] = count;
        return padded;
    }

    public static byte[] removePadding(byte[] padded) {
        int paddingLength = padded[padded.length - 1];
        byte[] content = new byte[padded.length - paddingLength];
        System.arraycopy(padded, 0, content, 0, content.length);
        return content;
    }

    public static byte[] encryptFile(byte[] data, byte[] key) {
        var paddData = addPadding(data, BLOCK_SIZE);
        int blocksLen = paddData.length / BLOCK_SIZE;
        var twofish = new TwofishAlgorithm(key);
        for (int i = 0; i < blocksLen; ++i) {
            var block = Arrays.copyOfRange(paddData, i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
            System.arraycopy(twofish.encrypt(block), 0, paddData, i * BLOCK_SIZE, BLOCK_SIZE);
        }
        return paddData;
    }


    public static byte[] decryptFile(byte[] data, byte[] key) {
        int blocksLen = data.length / BLOCK_SIZE;
        var twofish = new TwofishAlgorithm(key);
        for (int i = 0; i < blocksLen; ++i) {
            var block = Arrays.copyOfRange(data, i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
            System.arraycopy(twofish.decrypt(block), 0, data, i * BLOCK_SIZE, BLOCK_SIZE);
        }
        return removePadding(data);
    }


    public static byte[] recvTwoFishKey(DataInputStream in, DataOutputStream out) throws IOException {
        ElGamal eg = new ElGamal();
        eg.keyGen(1024);
        for (var i : eg.publicKey)
            out.writeUTF(i.toString());

        byte[] tfKey = new byte[16];
        for (int i = 0; i < 16; ++i)
            tfKey[i] = eg.decrypt(new BigInteger(in.readUTF()), new BigInteger(in.readUTF()));
        return tfKey;
    }

    public static void sendTwoFishKey(byte[] key, DataInputStream in, DataOutputStream out) throws IOException {
        ElGamal eg = new ElGamal();
        eg.keyGen(1024);
        for (int i = 0; i < 3; ++i)
            eg.publicKey.set(i, new BigInteger(in.readUTF()));
        for (int i = 0; i < 16; ++i) {
            List<BigInteger> enc = eg.encrypt(key[i]);
            out.writeUTF(enc.get(0).toString());
            out.writeUTF(enc.get(1).toString());
        }
    }
}

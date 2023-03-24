package org.example;

import com.google.common.io.BaseEncoding;
import com.googlecode.gwt.crypto.bouncycastle.AsymmetricBlockCipher;
import com.googlecode.gwt.crypto.bouncycastle.InvalidCipherTextException;
import com.googlecode.gwt.crypto.bouncycastle.encodings.OAEPEncoding;
import com.googlecode.gwt.crypto.bouncycastle.engines.RSAEngine;
import com.googlecode.gwt.crypto.bouncycastle.params.RSAPrivateCrtKeyParameters;

import java.math.BigInteger;
import java.util.Arrays;

public class LicenseKeyDecryptorImpl {
    private static AsymmetricBlockCipher ASYMMETRIC_BLOCK_CIPHER;
    private static byte[] CLIENT_DP;
    private static byte[] CLIENT_DQ;
    private static byte[] CLIENT_MODULUS;
    private static byte[] CLIENT_P;
    private static byte[] CLIENT_PRIVATE_EXPONENT;
    private static byte[] CLIENT_PUBLIC_EXPONENT;
    private static byte[] CLIENT_Q;
    private static byte[] CLIENT_Q_INV;
    private static int INPUT_BLOCK_SIZE;
    private static int OUTPUT_BLOCK_SIZE;
    private static RSAPrivateCrtKeyParameters RSA_PRIVATE_CRT_KEY_PARAMETERS;

    static {
        byte[] v0 = new byte[]{1, 0, 1};
        LicenseKeyDecryptorImpl.CLIENT_PUBLIC_EXPONENT = v0;
        byte[] v1 = new byte[]{-17, 67, 25, 13, (byte) 0x85, -104, -8, -25, -104, (byte) 0x87, -58, (byte) 0x7A, 54, -13, 107, 29, 40, (byte) 0x70, 99, 90, 28, (byte) 0x3F, -42, 89, -44, (byte) 0x79, (byte) 0x81, 46, 93, 72, -84, 11, -8, 44, 93, 2, 30, -110, -84, (byte) 0x20, 78, 72, -57, (byte) 0x3F, 45, -94, -77, (byte) 0x71, 42, (byte) 0x30, 61, -107, 109, -89, 89, (byte) 0x70, -66, (byte) 0x7B, -104, -97, -27, -53, (byte) 0x76, 72, 104, (byte) 0x8D, 99, -84, 35, -17, 92, (byte) 0xE1, 53, 36, (byte) 0x1F, -107, -58, (byte) 0x87, -86, -6, 40, 78, (byte) 0x7D, (byte) 0x82, -37, -106, 105, (byte) 0xA1, -80, 59, -15, -92, 83, -19, 16, -3, -89, -5, (byte) 0x8F, 50, -33, -5, (byte) 0x8A, 38, 99, -105, 39, 35, -4, 46, 43, -9, 91, -1, 60, -10, -7, (byte) 0x8C, (byte) 0x75, -120, 26, 15, 69, 103, (byte) 0x8B, 13, 77, 73};
//        System.out.println(TestScript.bytesToHex(v1));
        LicenseKeyDecryptorImpl.CLIENT_P = v1;
        byte[] v2 = new byte[]{-46, 78, 108, 24, 76, 105, 33, 14, 90, 0, 28, (byte) 0x87, (byte) 0x85, (byte) 0x8D, 43, 10, 29, 10, (byte) 0x20, -24, (byte) 0x6F, -23, -7, (byte) 0x89, (byte) 0x4F, -50, -75, -65, -80, 99, 68, -49, 15, -72, -103, 49, -33, (byte) 0x72, (byte) 0x5F, (byte) 0x70, -9, -86, -23, -24, (byte) 0x8A, -49, 28, 46, 40, -73, -67, -2, -54, -61, (byte) 0x91, 13, 60, 15, -7, (byte) 0x75, -120, (byte) 0xE0, 5, (byte) 0x3F, -10, 65, 28, (byte) 0x73, 24, 33, 59, 74, 1, 55, (byte) 0x87, -18, 75, 87, (byte) 0x3F, (byte) 0x2F, -106, -10, (byte) 0x82, -87, -46, -15, -73, 58, -19, -61, -110, -20, -36, 34, (byte) 0x8A, -22, -37, 93, -41, 89, 93, (byte) 0x7D, 11, -83, 103, (byte) 0x8B, 27, -6, -72, (byte) 0x8F, 42, -27, 54, 19, 85, -6, -30, -82, -17, 78, (byte) 0xB1, 101, 3, (byte) 0xC0, 107, -80, (byte) 0x8D, 83};
        LicenseKeyDecryptorImpl.CLIENT_Q = v2;
        byte[] v3 = new byte[]{67, -37, -53, -99, (byte) 0x87, 25, -76, 50, 4, -27, 5, 110, (byte) 0xE1, 103, 55, (byte) 0xA1, -39, (byte) 0x86, 72, 46, -108, -49, 110, -74, (byte) 0x76, -103, -55, (byte) 0x1F, 3, -59, -18, 23, 39, -66, (byte) 0xC1, -2, 58, 56, (byte) 0x77, 59, 66, -46, (byte) 0x1F, (byte) 0xE1, -70, (byte) 0x83, (byte) 0x20, -99, (byte) 0x8B, -33, 101, -34, 77, -56, -52, -83, 87, 94, 26, 5, 66, 109, -65, (byte) 0x84, -37, 41, 33, (byte) 0xE0, -106, -22, 2, -17, 70, -101, -62, (byte) 0x1F, 35, 70, (byte) 0xB1, (byte) 0x8F, -50, 55, -77, (byte) 0x81, (byte) 0x87, 49, -105, 19, 33, -6, 67, (byte) 0x75, 110, 54, -44, (byte) 0xD1, -66, -74, -68, (byte) 0x3F, -60, (byte) 0x2F, 93, -9, -23, -7, -59, -14, -52, 88, (byte) 0x87, -39, (byte) 0x60, 39, -67, (byte) 0xA1, 40, (byte) 0x73, 19, 97, 59, 9, 14, -28, -51, -92, 51, -45};
        LicenseKeyDecryptorImpl.CLIENT_Q_INV = v3;
        byte[] v4 = new byte[]{(byte) 0x7F, (byte) 0x8F, -7, (byte) 0x82, (byte) 0x71, 17, 14, -37, (byte) 0x83, 66, 24, (byte) 0x7A, -66, 99, 103, (byte) 0x5F, 99, 89, 16, (byte) 0x4F, 81, -78, 99, 88, -1, 100, 76, (byte) 0x90, 104, (byte) 0xA1, -65, (byte) 0x40, -98, (byte) 0x6F, (byte) 0x20, -93, 105, -93, (byte) 0x6F, 107, -59, -15, 29, (byte) 0x71, -68, -91, -5, (byte) 0x1F, (byte) 0xC1, (byte) 0x8B, 120, -71, -5, (byte) 0x7D, (byte) 0x76, -67, 26, (byte) 0x81, (byte) 0x90, -20, -25, 58, 99, -12, -44, -15, 85, 11, -55, 24, -20, (byte) 0x1F, 18, 19, 17, 87, -20, 66, 22, (byte) 0xD1, 74, -66, 22, 66, -73, 74, 105, 69, 16, 77, -43, 86, (byte) 0x74, (byte) 0x7C, (byte) 0x77, 75, -107, -51, 20, 26, -34, -70, (byte) 0x20, (byte) 0x7C, -71, 42, 52, (byte) 0x6F, 6, 27, -93, -53, 60, -36, 71, 39, -78, 2, -58, 2, -21, 73, -21, 9, -6, 99, -4, 41};
        LicenseKeyDecryptorImpl.CLIENT_DP = v4;
        byte[] v5 = new byte[]{25, 13, 108, (byte) 0x85, 12, (byte) 0x7D, 45, (byte) 0x89, -25, (byte) 0x20, -62, 69, 70, -100, (byte) 0x85, (byte) 0x77, 3, -12, -109, -20, -4, (byte) 0x7F, -13, (byte) 0xD0, -18, -89, -30, (byte) 0x30, -66, -109, 100, -68, 1, -44, 108, -77, 107, 57, -43, -78, (byte) 0xC0, 94, 36, -43, 37, -53, -4, (byte) 0x40, 103, 107, 83, -1, -55, 41, -72, -38, -55, -65, (byte) 0xE1, 104, -91, -16, (byte) 0x81, -49, -105, -57, 51, -37, 102, 17, (byte) 0x77, 93, -98, (byte) 0x7D, (byte) 0x7D, -4, -34, 14, -69, (byte) 0xA1, (byte) 0x30, -85, -106, -17, 34, 8, -41, 89, -10, -66, -24, (byte) 0x7E, -68, -50, (byte) 0x84, -101, -21, -101, -25, 46, 103, 27, (byte) 0xA1, 75, (byte) 0x7B, -35, (byte) 0x2F, 109, 19, -107, 66, (byte) 0x77, (byte) 0xE1, -108, 54, 22, -41, -16, 28, -29, -45, -16, 3, -99, 101, (byte) 0x76, -73, -81};
        LicenseKeyDecryptorImpl.CLIENT_DQ = v5;
        byte[] v6 = new byte[]{(byte) 0x8A, 100, -83, -84, -35, 88, 29, (byte) 0x2F, 97, -55, -58, 8, (byte) 0x81, -107, 15, 53, -49, 58, 17, -93, 35, -51, -33, 35, (byte) 0x79, (byte) 0x8F, 61, -46, -39, -9, (byte) 0x20, -92, 0, -19, 1, 84, -36, 73, (byte) 0x4F, -97, 97, (byte) 0x3F, -5, (byte) 0x81, -108, 50, -28, -14, 17, -59, -35, 59, -104, 90, 27, (byte) 0xD1, 35, 107, 8, 102, 107, -87, (byte) 0x74, -15, -9, -93, -72, -18, 2, -35, 97, 30, -73, 18, 105, 28, -86, -91, 29, -19, 9, 90, (byte) 0x83, (byte) 0xB1, (byte) 0xE1, (byte) 0x8A, 1, 46, 36, -13, 78, -34, (byte) 0x7A, 91, (byte) 0xE1, 56, 54, (byte) 0x4F, -27, 11, 23, 59, -34, 6, 87, 102, -72, 9, 23, -27, 35, -104, -68, -92, 98, 27, 58, 5, 84, 15, (byte) 0x86, (byte) 0x60, -89, 2, 73, 51, -87, -1, 66, 99, 25, -19, (byte) 0x84, -90, -19, (byte) 0x90, 91, 49, -49, -109, (byte) 0x86, (byte) 0x80, 75, -52, 16, (byte) 0x85, 43, 13, -60, (byte) 0x76, -73, -56, -26, -9, -70, -92, -84, (byte) 0x74, -39, -100, (byte) 0x80, -69, (byte) 0x5F, 15, (byte) 0x82, 23, -57, 20, -81, (byte) 0x73, -14, 15, 50, -13, 59, -28, 54, -55, 62, -29, -20, 5, -66, -72, -69, -66, -55, (byte) 0x5F, 88, -5, 17, -2, 26, (byte) 0x70, -4, 15, 81, -42, -73, 52, 46, -59, (byte) 0x30, -41, (byte) 0x8F, -77, -11, (byte) 0xC0, -50, -5, (byte) 0x81, -1, 26, (byte) 0x7E, -73, -33, -33, (byte) 0x83, 78, -72, -76, 110, -88, (byte) 0x30, 36, 19, -52, 25, -70, 68, 55, (byte) 0xC1, (byte) 0x77, 62, (byte) 0x82, (byte) 0x7C, 38, -92, -82, 16, 106, 76, 0, (byte) 0x90, 13, 21, 15, -9, -53, 82, 66, (byte) 0x73, -10, -72, (byte) 0x84, 1};
        LicenseKeyDecryptorImpl.CLIENT_PRIVATE_EXPONENT = v6;
        byte[] v7 = new byte[]{-60, (byte) 0x8E, 86, 5, -67, -4, 107, 69, 59, 65, -24, (byte) 0x4F, -18, 105, 49, 15, 20, -37, -9, 73, 21, -109, 94, 2, -97, 89, 109, (byte) 0x8C, 97, -78, (byte) 0x91, 4, 23, (byte) 0x87, 74, -110, -50, 26, (byte) 0x84, -87, -3, -80, 69, 62, -18, -28, -97, 69, -27, 83, 88, 107, 43, -53, 7, -78, 60, (byte) 0xB1, -58, 56, -66, 102, -53, (byte) 0x3F, (byte) 0x72, -50, 52, -91, -54, (byte) 0x72, -30, (byte) 0x82, 22, 73, 82, 71, -43, 12, 30, -94, -42, 36, -1, -74, -75, 106, 0, (byte) 0x4F, -66, -38, -90, -97, (byte) 0x79, 102, 105, 53, -66, -74, -89, 98, 84, -26, 5, 86, -109, -103, -45, (byte) 0xE1, -24, (byte) 0x77, (byte) 0xA1, (byte) 0x8A, -89, 55, -22, 86, -54, (byte) 0x90, -15, (byte) 0x8E, (byte) 0xE1, -69, 94, -93, -13, (byte) 0x84, 94, 6, -98, (byte) 0x40, -71, 20, 60, -93, -18, -13, 39, -51, 92, (byte) 0x77, -67, 82, (byte) 0x87, -86, 23, 106, (byte) 0x83, -89, -90, 27, -106, -72, 89, (byte) 0x8B, (byte) 0x82, 1, (byte) 0x71, -107, -11, -20, 56, 80, -72, -42, (byte) 0x70, (byte) 0x91, 88, (byte) 0x81, -13, -6, -6, -85, -89, 106, 66, (byte) 0x70, 6, (byte) 0xD1, -23, 93, -57, 98, 70, -52, -59, -104, 6, -74, 28, (byte) 0x71, 34, -70, -82, (byte) 0x3F, 46, 26, -78, 40, 20, 37, 99, 15, 34, (byte) 0xE1, -49, 46, -43, (byte) 0x81, -44, 50, (byte) 0xA1, -78, -78, -57, -55, 84, -62, 13, -6, 18, 23, -57, -80, -84, 56, (byte) 0x73, -15, 70, 84, 1, (byte) 0x8F, -46, -94, 77, (byte) 0x30, (byte) 0xA0, -120, (byte) 0x2F, 18, -5, -13, (byte) 0x84, 110, (byte) 0x87, 106, (byte) 0xD1, 100, 51, 67, 42, (byte) 0x82, 91, 14, 17, 67, -85};
        LicenseKeyDecryptorImpl.CLIENT_MODULUS = v7;
        RSAPrivateCrtKeyParameters v2_1 = new RSAPrivateCrtKeyParameters(new BigInteger(1, v7), new BigInteger(1, v0), new BigInteger(1, v6), new BigInteger(1, v1), new BigInteger(1, v2), new BigInteger(1, v4), new BigInteger(1, v5), new BigInteger(1, v3));

        LicenseKeyDecryptorImpl.RSA_PRIVATE_CRT_KEY_PARAMETERS = v2_1;
        OAEPEncoding v0_1 = new OAEPEncoding(new RSAEngine());
        LicenseKeyDecryptorImpl.ASYMMETRIC_BLOCK_CIPHER = v0_1;
        v0_1.init(false, v2_1);
        LicenseKeyDecryptorImpl.INPUT_BLOCK_SIZE = v0_1.getInputBlockSize();
        LicenseKeyDecryptorImpl.OUTPUT_BLOCK_SIZE = v0_1.getOutputBlockSize();
    }


    public static byte[] decryptLicenseKey(String arg11) {
        try {
            byte[] v11_2 = BaseEncoding.base64Url().decode(arg11);
            byte[] v1 = new byte[LicenseKeyDecryptorImpl.OUTPUT_BLOCK_SIZE];
            int v2 = v11_2.length;
            int v4 = 0;
            int v5 = 0;
            while(v2 > 0) {
                int v6 = Math.min(LicenseKeyDecryptorImpl.INPUT_BLOCK_SIZE, v2);
                byte[] v7 = LicenseKeyDecryptorImpl.ASYMMETRIC_BLOCK_CIPHER.processBlock(v11_2, v5, v6);
                int v8 = v7.length + v4;
                if(v8 > v1.length) {
                    byte[] v8_1 = new byte[v8];
                    System.arraycopy(((Object)v1), 0, ((Object)v8_1), 0, v4);
                    v1 = v8_1;
                }

                System.arraycopy(((Object)v7), 0, ((Object)v1), v4, v7.length);
                v4 += v7.length;
                v5 += v6;
                v2 -= v6;
            }

//            arg12.onDecrypted(Arrays.copyOf(v1, v4));
//            System.out.println("Decrypt License: " + Arrays.copyOf(v1, v4));
            return Arrays.copyOf(v1, v4);
        }
        catch(InvalidCipherTextException v11_1) {
//            arg12.onFailed(new DRMException(DRMFailureReason.INVALID_LICENSE, "Could not decrypt license key", v11_1));
            v11_1.printStackTrace();
        }
        catch(RuntimeException v11) {
//            arg12.onFailed(new DRMException(DRMFailureReason.UNDEFINED, "Could not decrypt license key", v11));
            v11.printStackTrace();
        }
        return null;
    }
}

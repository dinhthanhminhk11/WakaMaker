package org.example;

import com.googlecode.gwt.crypto.bouncycastle.engines.AESEngine;
import com.googlecode.gwt.crypto.bouncycastle.modes.CBCBlockCipher;
import com.googlecode.gwt.crypto.bouncycastle.paddings.PaddedBufferedBlockCipher;
import com.googlecode.gwt.crypto.bouncycastle.params.KeyParameter;
import com.googlecode.gwt.crypto.bouncycastle.params.ParametersWithIV;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws IOException {
        String license = "rZUTDmc7k5lhkYAhdq2pFg62-llXYG_FmpL0-iNJSwVN0knpUZkcspODyS7mRx7_WQ6zo8a3PWU4wdRj40euWeg8q89pwG5fK6rHNbtKNsv7h9xHi09siW_xKKPRHlKm76nrh2QNtVBWlwDI3daZuAh8EovFGnEaMhOJ2MlvJlQdib62uodEDKsHCfruMenl42IEorC512Ycms6cTOvwkAIfCK_j75PZzqj1eSZb8B5eApRQZpGfZoYmutKowYJaJBnmn2q6Wf7K9eL4TuYPHT36YZKfuzsty0lECWnaAXtJEU2nEuSnAZNP5x1Td9_70vgpxGPdAk7qY6RFITGMnw$B2jX_i2uh0ZICeZwZySVWnfSE5aHYaw7ED310e1xxfFLLmC43XmXZdeCWJxmfHdT$Ty_iEspmWKe6IsHTL1TVzw";
        String[] sps = license.split("\\$");
        String v0 = sps[0];
        byte[] licenseDecrypted = LicenseKeyDecryptorImpl.decryptLicenseKey(v0);
        {
//        System.out.println("licenseDec " + Arrays.toString(licenseDecrypted));
//        byte[] part1Decrypted = DRMSession.decryptLicenseContent(licenseDecrypted, sps[1]);
//        byte[] part2Decrypted = DRMSession.decryptLicenseContent(part1Decrypted, sps[2]);
//        System.out.println("Part2 dec: " + new String(part2Decrypted));
//        DRMLicense drmLicense = DRMLicense.valueOf("RSA-OAEP", sps[0], 0, true);
//        System.out.println("Drm: " + drmLicense.encode());
        }

        for(int i = 10; i <= 18; i++) {
            String fI = "C:\\Users\\ADMIN\\Desktop\\mohinhkinhdoanh\\OEBPS\\contents\\Section00" + i + ".xhtml";
            String fO = "C:\\\\Users\\\\ADMIN\\\\Desktop\\\\mohinhkinhdoanh\\\\OEBPS\\\\contents\\\\Section00" + i + "_dec.xhtml";
            File f = new File(fI);
            byte[] data = FileUtils.readFileToByteArray(f);
            byte[] result = decrypt(licenseDecrypted, data);
            System.out.println("Content: " + new String(result));
            FileUtils.writeByteArrayToFile(new File(fO), result);
        }
    }

    public static byte[] decrypt(byte[] key, byte[] input) {
        int v0 = key.length / 2;
        ParametersWithIV v1 = new ParametersWithIV(new KeyParameter(key, v0, v0), key, 0, v0);
        int v7 = input.length;
        int v6 = 0;
        byte[] v5 = input;
        try {
            PaddedBufferedBlockCipher v11_1 = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
            v11_1.init(false, v1);
            byte[] v12_1 = new byte[v11_1.getOutputSize(v7)];
            int v0_1 = v11_1.processBytes(v5, v6, v7, v12_1, 0);
            return Arrays.copyOf(v12_1, v0_1 + v11_1.doFinal(v12_1, v0_1));
        }
        catch(Exception v11) {
            v11.printStackTrace();
        }
        return null;
    }
}
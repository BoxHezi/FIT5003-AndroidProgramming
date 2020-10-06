/*
 * Copyright (C) 2012-2019 Japan Smartphone Security Association
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jssec.android.activity.privateactivity;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.Intent;
import android.content.res.AssetManager;
import android.os.Build;
import android.os.Bundle;

import android.os.Message;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import org.w3c.dom.Text;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

import java.security.MessageDigest;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//Appropriate libraries need to be also imported

public class PrivateActivity extends Activity {
    private KeyStore my_ks;
    private static final String key = "aesEncryptionKey";
    private static final String initVector = "encryptionIntVec";
    private PrivateUserActivity.user_info param;
    private char[] keyStorePassword;


    /// The following are methods that you may find of use:
    public String byteToHex(byte num) {   //This method transforms a byte into a hexadecimal string
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }

    public String encodeHexString(byte[] byteArray) { //This method transforms a byte array into a hexadecimal string
        StringBuffer hexStringBuffer = new StringBuffer();
        for (int i = 0; i < byteArray.length; i++) {
            hexStringBuffer.append(byteToHex(byteArray[i]));
        }
        return hexStringBuffer.toString();
    }

    private byte[] extractbytes(byte[] input, int len) {  // This method extracts from a byte array a specific amount of bytes (given by the parameter len)

        ByteBuffer bb = ByteBuffer.wrap(input);

        byte[] output = new byte[len];
        bb.get(output, 0, output.length);
        return output;
    }


    @TargetApi(Build.VERSION_CODES.KITKAT)
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.private_activity);

        Intent intent = this.getIntent();
        param = (PrivateUserActivity.user_info) intent.getSerializableExtra("CL_k");

        String process_ks_pass = param.getPassword_val() + param.getKeystore_user();

        /// HERE you need to add the appropriate code for validating the user and the user password (following the specifications of the assignment)
        // Also to open the appropriate keystore and to visualize all keystore information.

        byte[] hashResult = calculateHash(process_ks_pass); // calculate hash of password + username
        hashResult = extractbytes(hashResult, 5);
        String hashResultStr = encodeHexString(hashResult);
        keyStorePassword = hashResultStr.toCharArray();

        try {
            displayKeyStoreData(); // display keystore data
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            // when keystore password check fail, it goes to here
            Intent intentResult = getIntent();
            String msg = "Please check your username and password";
            intentResult.putExtra("msg", msg);
            setResult(RESULT_CANCELED, intentResult);
            finish();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }


        // In this Android project there is a keystore called fit5003_keystore.jks in the assets folder of the app
        // The keystore has been configured for a user with:
        // username: user1
        // password: pas1
        // Following the assignment specifications:
        // The concatenation of the provided credentials is: pas1user1
        // the SHA256 hash value is  7cbbdea6ada60362907940a1fbd398dbcba685d95a3d762a893fcc3bb815e8ad
        // Taking the first 5 bytes acts as the keystore password: 7cbbdea6ad
        // thus the keystore password is 7cbbdea6ad
        // The various keystore entries passwords is the same as the keystore password
        // The keystore type is bks (Android does not support jks keystores)


    }

    @TargetApi(Build.VERSION_CODES.O)
    public void onReturnResultClick(View view) {


        // Grab the EditText objects from phone screen
        EditText alias = findViewById(R.id.editText2);
        TextView sms_text = findViewById(R.id.sms_entr);
        EditText sms_tel = findViewById(R.id.sms_tel);

        // HERE CODE must be added so as to securely sent SMS following the appropriate Assignment specifications
        // Also the result of the activity should be send as a Base64 encoded String to PrivateUserActivity.java

        //---------------------------------

        finish();
    }

    /**
     * calculate given string's hash using SHA256 algorithm
     *
     * @param strToHash string to hash
     * @return hashed string, null if reach no such algorithm exception
     */
    private byte[] calculateHash(String strToHash) {
        final String HASH_ALGORITHM = "SHA-256";
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
            return md.digest(strToHash.getBytes());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * display keystore information in the text view area
     *
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    private void displayKeyStoreData() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        my_ks = KeyStore.getInstance("BKS");

        // open keystore file
        AssetManager am = this.getAssets();
        InputStream keyStoreData = am.open("fit5003_keystore.jks");

        my_ks.load(keyStoreData, keyStorePassword); // load keystore file data

        TextView textView = (TextView) findViewById(R.id.alias_text);
        Enumeration<String> aliases = my_ks.aliases(); // get all aliases from keystore file

        StringBuilder sb = new StringBuilder();
        while (aliases.hasMoreElements()) { // loop through each alias and get certificate type, display them
            String alias = aliases.nextElement();

            Certificate certificate = my_ks.getCertificate(alias);
            String certType = certificate.getType();

            sb.append("Alias: ").append(alias).append(" ").append("Certificate Type: ").append(certType).append("\n");
        }

        textView.setText(sb);
    }
}

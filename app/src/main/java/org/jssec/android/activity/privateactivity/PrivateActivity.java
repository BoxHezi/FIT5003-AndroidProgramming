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
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.AssetManager;
import android.hardware.SensorDirectChannel;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;

import android.os.Message;
import android.telephony.SmsManager;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import org.w3c.dom.Text;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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
import java.util.Arrays;
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

    private String userAlias; // user alias in order to get current user's private key


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
        userAlias = param.getKeystore_user();

        /// HERE you need to add the appropriate code for validating the user and the user password (following the specifications of the assignment)
        // Also to open the appropriate keystore and to visualize all keystore information.

        try {
            byte[] hashResult = calculateHash(process_ks_pass); // calculate hash of password + username
            hashResult = extractbytes(hashResult, 5);
            String hashResultStr = encodeHexString(hashResult);
            keyStorePassword = hashResultStr.toCharArray();
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
    public void onReturnResultClick(View view) throws KeyStoreException, NoSuchPaddingException, InvalidKeyException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
            UnrecoverableKeyException, SignatureException {


        // Grab the EditText objects from phone screen
        EditText alias = findViewById(R.id.editText2);
        TextView sms_text = findViewById(R.id.sms_entr);
        EditText sms_tel = findViewById(R.id.sms_tel);

        // HERE CODE must be added so as to securely sent SMS following the appropriate Assignment specifications
        // Also the result of the activity should be send as a Base64 encoded String to PrivateUserActivity.java

        //---------------------------------

        // Get public key from chosen alias
        Certificate certificate = my_ks.getCertificate(alias.getText().toString());
        if (certificate == null) { // when alias chosen is not exist
            String msg = "Alias not exist, please check your selected alias";
            Toast.makeText(this, String.format("Received result: \"%s\"", msg), Toast.LENGTH_LONG).show();
        } else {
            PublicKey pk = certificate.getPublicKey(); // get public key of input alias
            String[] cipher = encrypt(pk, sms_text.getText().toString());

            String smsCipher = cipher[0]; // encrypted sms
            String skCipher = cipher[1]; // encrypted secret key

            // concatenate encrypted sms and encrypted secret key
            // add a space as self-define flag to separate smsCipher and secure key cipher
            String smsContent = smsCipher + " " + skCipher;

            // show sms content below alias area
            TextView textView = (TextView) findViewById(R.id.alias_text);
            textView.append(smsContent);
            sendSms(smsContent, sms_tel.getText().toString());

            // Get user's private key
            PrivateKey privateKey = (PrivateKey) my_ks.getKey(userAlias, keyStorePassword);
            String signature = signMessage(smsContent, privateKey);

            Intent intentResult = new Intent();
            intentResult.putExtra("signature", signature);
            setResult(RESULT_OK, intentResult);
            finish();
        }
    }

    /**
     * calculate given string's hash using SHA256 algorithm
     *
     * @param strToHash string to hash
     * @return hashed string, null if reach no such algorithm exception
     */
    private byte[] calculateHash(String strToHash) throws NoSuchAlgorithmException {
        final String HASH_ALGORITHM = "SHA-256";
        MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
        return md.digest(strToHash.getBytes());
    }

    /**
     * display keystore information in the text view area
     *
     * @throws KeyStoreException
     * @throws IOException              when password for keystore is wrong
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

    /**
     * encrypt algorithm, symmetric key will be generated within this stage
     *
     * @param pk  public key which is used to encrypt symmetric key
     * @param msg sms text to encrypt
     * @return A string array contains encrypted sms and encrypted symmetric key, both in base64 encoded
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    @TargetApi(Build.VERSION_CODES.O)
    private String[] encrypt(PublicKey pk, String msg) throws NoSuchAlgorithmException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {

        // Generate AES key
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256); // define key size
        SecretKey sk = kg.generateKey(); // generate secret key

        String smsCipherBase64 = encryptSms(sk, msg);
        String encryptedSKBase64 = encryptSecretKey(pk, sk);

        return new String[]{smsCipherBase64, encryptedSKBase64};
    }

    /**
     * encrypt sms text using AES CBC mode
     * IV will be randomly generated within the method
     *
     * @param sk  secret key to encrypt sms
     * @param sms sms to be encrypted
     * @return encrypted sms in base64 format
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    @TargetApi(Build.VERSION_CODES.O)
    private String encryptSms(SecretKey sk, String sms) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecureRandom sr = new SecureRandom(); // create a new SecureRandom instance in order to randomly generate IV
        byte[] iv = new byte[cipher.getBlockSize()];
        sr.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, sk, ivParameterSpec); // init cipher using encrypt, secret key and iv

        byte[] smsCipher = cipher.doFinal(sms.getBytes()); // encrypt sms text
        return new String(Base64.getEncoder().encode(smsCipher)); // convert to base64 and return
    }

    /**
     * encrypt sk using pk
     *
     * @param pk public key use for encryption
     * @param sk secret key need to be encrypted
     * @return encrypted sk in base64 format string
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     */
    @TargetApi(Build.VERSION_CODES.O)
    private String encryptSecretKey(PublicKey pk, SecretKey sk) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        // using wrap mode because here is going to encrypt key. Cipher.unwrap() returns a Key
        // reference: https://stackoverflow.com/questions/16586627/should-i-use-cipher-wrap-mode-or-cipher-encrypt-mode-to-encrypt-a-session-key
        cipher.init(Cipher.WRAP_MODE, pk);

        byte[] wrapperKey = cipher.wrap(sk);
        return new String(Base64.getEncoder().encode(wrapperKey)); // convert to base64 and return
    }

    /**
     * sending text message
     *
     * @param sms         content need to be sent
     * @param phoneNumber receiver's phone number
     */
    private void sendSms(String sms, String phoneNumber) {
        // SmsManager has limitation of 160 char for each sms
        // when the content length is larger than 160 use sendMultipartTextMessage instead
        // reference: https://stackoverflow.com/questions/24234731/what-is-the-limited-of-chars-for-smsmanager
        // https://stackoverflow.com/questions/1981430/sending-long-sms-messages
        // https://stackoverflow.com/questions/6580675/how-to-send-the-sms-more-than-160-character

        SmsManager smsManager = SmsManager.getDefault();
        if (sms.length() < 160) {
            smsManager.sendTextMessage(phoneNumber, null, sms, null, null);
        } else {
            ArrayList<String> smsList = smsManager.divideMessage(sms); // covert original sms to array list
            smsManager.sendMultipartTextMessage(phoneNumber, null, smsList, null, null);
        }
    }

    /**
     * sign msg need to be sent
     *
     * @param msg        msg content will be sent
     * @param privateKey private key to sign msg
     * @return signature in hexadecimal format
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws InvalidKeyException
     */
    private String signMessage(String msg, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException,
            InvalidKeyException {
        final String signatureAlgorithm = "SHA256withRSA";
        Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initSign(privateKey);
        signature.update(msg.getBytes());

        byte[] signed = signature.sign();
        return encodeHexString(signed); // convert signature to string and return
    }
}

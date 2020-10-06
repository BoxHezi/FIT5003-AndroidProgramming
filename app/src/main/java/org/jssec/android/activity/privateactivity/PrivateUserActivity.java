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


import android.app.Activity;
import android.content.Intent;

import android.os.Bundle;

import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.View;
import android.view.WindowManager;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.Toast;

import java.io.IOException;

import java.io.Serializable;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import java.security.cert.*;


public class PrivateUserActivity extends Activity {

    public static class user_info implements Serializable {
        String username;
        String password_val;

        public void user_info() {
            this.username = "";
            this.password_val = "";
        }

        public void setKeystore_user(String usernm) {
            this.username = usernm;
        }

        public void setPassword_val(String pass_val) {
            this.password_val = pass_val;
        }

        public String getPassword_val() {
            return password_val;
        }

        public String getKeystore_user() {
            return username;
        }
    }


    private static final int REQUEST_CODE = 1;

    // Key to save the state
    private static final String KEY_DUMMY_PASSWORD = "KEY_DUMMY_PASSWORD";

    // View inside Activity
    private EditText mPasswordEdit;
    private CheckBox mPasswordDisplayCheck;

    // Flag to show whether password is dummy display or not
    private boolean mIsDummyPassword;


    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.user_activity);
        // Set Disabling Screen Capture
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);

        // Get View
        mPasswordEdit = (EditText) findViewById(R.id.password_edit);
        mPasswordDisplayCheck =
                (CheckBox) findViewById(R.id.password_display_check);

        // Whether last Input password exist or not.
        if (getPreviousPassword() != null) {
            // In the case there is the last input password in
            // an initial display, display the fixed digit numbers of black dot
            // as dummy in order not that the digits number of last password
            // is guessed.

            // Display should be dummy password.
            mPasswordEdit.setText("**********");
            // To clear the dummy password when inputting password, set text
            // change listener.
            mPasswordEdit.addTextChangedListener(new PasswordEditTextWatcher());
            // Set dummy password flag
            mIsDummyPassword = true;
        }

        // Set a listner to change check state of password display option.
        mPasswordDisplayCheck.setOnCheckedChangeListener(new OnPasswordDisplayCheckedChangeListener());


    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);

        // Unnecessary when specifying not to regenerate Activity by the change in
        // screen aspect ratio.
        // Save Activity state
        outState.putBoolean(KEY_DUMMY_PASSWORD, mIsDummyPassword);
    }

    @Override
    public void onRestoreInstanceState(Bundle savedInstanceState) {
        super.onRestoreInstanceState(savedInstanceState);

        // Unnecessary when specifying not to regenerate Activity by the change in
        // screen aspect ratio.
        // Restore Activity state
        mIsDummyPassword = savedInstanceState.getBoolean(KEY_DUMMY_PASSWORD);
    }

    /**
     * Process in case password is input
     */
    private class PasswordEditTextWatcher implements TextWatcher {

        public void beforeTextChanged(CharSequence s, int start, int count,
                                      int after) {
            // Not used
        }

        public void onTextChanged(CharSequence s, int start, int before,
                                  int count) {
            // When last Input password is displayed as dummy,
            // in the case an user tries to input password, Clear the last
            // input password, and treat new user input as new password.
            if (mIsDummyPassword) {
                // Set dummy password flag
                mIsDummyPassword = false;
                // Trim space
                CharSequence work = s.subSequence(start, start + count);
                mPasswordEdit.setText(work);
                // Cursor position goes back the beginning, so bring it at the end.
                mPasswordEdit.setSelection(work.length());
            }
        }

        public void afterTextChanged(Editable s) {
            // Not used
        }

    }


    /**
     * Process when check of password display option is changed.
     */
    private class OnPasswordDisplayCheckedChangeListener
            implements CompoundButton.OnCheckedChangeListener {

        public void onCheckedChanged(CompoundButton buttonView,
                                     boolean isChecked) {
            // When the dummy password is displayed and the
            // "Show password" button is pressed, clear the last input
            // password and provide the state for new password input.
            if (mIsDummyPassword && isChecked) {
                // Set dummy password flag
                mIsDummyPassword = false;
                // Set password empty
                mPasswordEdit.setText(null);
            }

            // Cursor position goes back the beginning, so memorize the current
            // cursor position.
            int pos = mPasswordEdit.getSelectionStart();

            // Provide the option to display the password in a
            // plain text
            // Create InputType
            int type = InputType.TYPE_CLASS_TEXT;
            if (isChecked) {
                // Plain display when check is ON.
                type |= InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD;
            } else {
                // Masked display when check is OFF.
                type |= InputType.TYPE_TEXT_VARIATION_PASSWORD;
            }

            // Set InputType to password EditText
            mPasswordEdit.setInputType(type);

            // Set cursor position
            mPasswordEdit.setSelection(pos);
        }

    }

    // Implement the following method depends on application

    /**
     * Get the last Input password
     *
     * @return Last Input password
     */
    private String getPreviousPassword() {
        // When need to restore the saved password, return password character
        // string
        // For the case password is not saved, return null
        return "fit5003";
    }

    /**
     * Process when cancel button is clicked
     *
     * @param view
     */
    public void onClickCancelButton(View view) {
        // Close Activity
        finish();
    }

    /**
     * Process when OK button is clicked
     *
     * @param view
     */


    //----------------------------------------------------------------------
    public void onUseActivityClick(View view) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {

        EditText username_obj = (EditText) findViewById(R.id.username);

        user_info ks_f = new user_info();
        ks_f.setKeystore_user(username_obj.getText().toString());

        //---

        String password = null;

        if (mIsDummyPassword) {
            // When dummy password is displayed till the final moment, grant last
            // input password as fixed password.
            password = getPreviousPassword();
        } else {
            // In case of not dummy password display, grant the user input
            // password as fixed password.
            password = mPasswordEdit.getText().toString();
        }

        // Example: You can display password by Toast
        //Toast.makeText(this, "password is \"" + password + "\"", Toast.LENGTH_SHORT).show();

        ks_f.setPassword_val(mPasswordEdit.getText().toString());


        Intent sendIntent = new Intent();
        sendIntent.setAction(Intent.ACTION_SEND);
        //sendIntent.addCategory(Intent.CATEGORY_INFO);
        sendIntent.putExtra("CL_k", ks_f);


        startActivityForResult(sendIntent, REQUEST_CODE);

    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        // ADD appropriate code HERE so that the result can be captured.

        if (requestCode == REQUEST_CODE) {
            if (resultCode == RESULT_CANCELED) {
                String msg = data.getStringExtra("msg");
                Toast.makeText(this, String.format("Received result: \"%s\"", msg), Toast.LENGTH_LONG).show();
            } else if (resultCode == RESULT_OK) {
                System.out.println("RESULT_OK");
            }
        }

        //You can use the Toast class to view the result as follows:
        //Toast.makeText(this,  String.format("Received result: \"%s\"", result),Toast.LENGTH_LONG).show();


    }
}

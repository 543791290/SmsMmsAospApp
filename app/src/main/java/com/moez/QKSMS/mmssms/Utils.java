/*
 * Copyright (C) 2015 QK Labs
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
package com.moez.QKSMS.mmssms;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AuthenticatorException;
import android.accounts.OperationCanceledException;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.ConnectivityManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.provider.Telephony;
import android.provider.Telephony.Sms;
import android.telephony.SmsMessage;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.util.Log;

import com.google.android.mms.util_alt.SqliteWrapper;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Common methods to be used for data connectivity/sending messages ect
 */
public class Utils {
    private static final String TAG = "Utils";
    private static final boolean LOCAL_LOGV = false;
    /**
     * characters to compare against when checking for 160 character sending compatibility
     */
    public static final String GSM_CHARACTERS_REGEX = "^[A-Za-z0-9 \\r\\n@Ł$ĽčéůěňÇŘřĹĺ\u0394_\u03A6\u0393\u039B\u03A9\u03A0\u03A8\u03A3\u0398\u039EĆćßÉ!\"#$%&'()*+,\\-./:;<=>?ĄÄÖŃÜ§żäöńüŕ^{}\\\\\\[~\\]|\u20AC]*$";

    /**
     * Gets the current users phone number
     *
     * @param context is the context of the activity or service
     * @return a string of the phone number on the device
     */
    public static String getMyPhoneNumber(Context context) {
        TelephonyManager mTelephonyMgr;
        mTelephonyMgr = (TelephonyManager)
                context.getSystemService(Context.TELEPHONY_SERVICE);
        return mTelephonyMgr.getLine1Number();
    }

    /**
     * Enable mobile connection for a specific address
     *
     * @param address the address to enable
     * @return true for success, else false
     */
    public static void forceMobileConnectionForAddress(ConnectivityManager mConnMgr, String address) {
        //find the host name to route
        String hostName = extractAddressFromUrl(address);
        if (TextUtils.isEmpty(hostName)) hostName = address;

        //create a route for the specified address
        int hostAddress = lookupHost(hostName);
        mConnMgr.requestRouteToHost(ConnectivityManager.TYPE_MOBILE_MMS, hostAddress);
    }

    /**
     * Function for getting the weird auth token used to send or receive google voice messages
     *
     * @param account is the string of the account name to get the auth token for
     * @param context is the context of the activity or service
     * @return a string of the auth token to be saved for later
     * @throws java.io.IOException
     * @throws android.accounts.OperationCanceledException
     * @throws android.accounts.AuthenticatorException
     */
    public static String getAuthToken(String account, Context context) throws IOException, OperationCanceledException, AuthenticatorException {
        Bundle bundle = AccountManager.get(context).getAuthToken(new Account(account, "com.google"), "grandcentral", true, null, null).getResult();
        return bundle.getString(AccountManager.KEY_AUTHTOKEN);
    }

    /**
     * This method extracts from address the hostname
     *
     * @param url eg. http://some.where.com:8080/sync
     * @return some.where.com
     */
    public static String extractAddressFromUrl(String url) {
        String urlToProcess = null;

        //find protocol
        int protocolEndIndex = url.indexOf("://");
        if (protocolEndIndex > 0) {
            urlToProcess = url.substring(protocolEndIndex + 3);
        } else {
            urlToProcess = url;
        }

        // If we have port number in the address we strip everything
        // after the port number
        int pos = urlToProcess.indexOf(':');
        if (pos >= 0) {
            urlToProcess = urlToProcess.substring(0, pos);
        }

        // If we have resource location in the address then we strip
        // everything after the '/'
        pos = urlToProcess.indexOf('/');
        if (pos >= 0) {
            urlToProcess = urlToProcess.substring(0, pos);
        }

        // If we have ? in the address then we strip
        // everything after the '?'
        pos = urlToProcess.indexOf('?');
        if (pos >= 0) {
            urlToProcess = urlToProcess.substring(0, pos);
        }
        return urlToProcess;
    }

    /**
     * Transform host name in int value used by ConnectivityManager.requestRouteToHost
     * method
     *
     * @param hostname
     * @return -1 if the host doesn't exists, elsewhere its translation
     * to an integer
     */
    public static int lookupHost(String hostname) {
        InetAddress inetAddress;

        try {
            inetAddress = InetAddress.getByName(hostname);
        } catch (UnknownHostException e) {
            return -1;
        }

        byte[] addrBytes;
        int addr;
        addrBytes = inetAddress.getAddress();
        addr = ((addrBytes[3] & 0xff) << 24)
                | ((addrBytes[2] & 0xff) << 16)
                | ((addrBytes[1] & 0xff) << 8)
                | (addrBytes[0] & 0xff);

        return addr;
    }

    /**
     * Ensures that the host MMSC is reachable
     *
     * @param context is the context of the activity or service
     * @param url     is the MMSC to check
     * @param proxy   is the proxy of the APN to check
     * @throws java.io.IOException when route cannot be established
     */
    public static void ensureRouteToHost(Context context, String url, String proxy) throws IOException {
        ConnectivityManager connMgr =
                (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        connMgr.startUsingNetworkFeature(ConnectivityManager.TYPE_MOBILE_HIPRI, "enableMMS");

        if (LOCAL_LOGV) Log.v(TAG, "ensuring route to host");

        int inetAddr;
        if (proxy != null && !proxy.equals("")) {
            String proxyAddr = proxy;
            inetAddr = lookupHost(proxyAddr);
            if (inetAddr == -1) {
                throw new IOException("Cannot establish route for " + url + ": Unknown host");
            } else {
                if (!connMgr.requestRouteToHost(
                        ConnectivityManager.TYPE_MOBILE_MMS, inetAddr)) {
                    throw new IOException("Cannot establish route to proxy " + inetAddr);
                }
            }
        } else {
            Uri uri = Uri.parse(url);
            inetAddr = lookupHost(uri.getHost());
            if (inetAddr == -1) {
                throw new IOException("Cannot establish route for " + url + ": Unknown host");
            } else {
                if (!connMgr.requestRouteToHost(
                        ConnectivityManager.TYPE_MOBILE_MMS, inetAddr)) {
                    throw new IOException("Cannot establish route to " + inetAddr + " for " + url);
                }
            }
        }
    }

    /**
     * Checks whether or not mobile data is enabled and returns the result
     *
     * @param context is the context of the activity or service
     * @return true if data is enabled or false if disabled
     */
    public static Boolean isMobileDataEnabled(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);

        try {
            Class<?> c = Class.forName(cm.getClass().getName());
            Method m = c.getDeclaredMethod("getMobileDataEnabled");
            m.setAccessible(true);
            return (Boolean) m.invoke(cm);
        } catch (Exception e) {
            Log.e(TAG, "exception thrown", e);
            // Make sure to return FALSE instead of null, or else you will get a NPE when you try
            // to access the boolean value of this.
            return Boolean.FALSE;
        }
    }

    /**
     * Toggles mobile data
     *
     * @param context is the context of the activity or service
     * @param enabled is whether to enable or disable data
     */
    public static void setMobileDataEnabled(Context context, boolean enabled) {
        if (PreferenceManager.getDefaultSharedPreferences(context).getBoolean("pref_key_auto_data", true)) {
            try {
                ConnectivityManager conman = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
                Class conmanClass = Class.forName(conman.getClass().getName());
                Field iConnectivityManagerField = conmanClass.getDeclaredField("mService");
                iConnectivityManagerField.setAccessible(true);
                Object iConnectivityManager = iConnectivityManagerField.get(conman);
                Class iConnectivityManagerClass = Class.forName(iConnectivityManager.getClass().getName());
                Method setMobileDataEnabledMethod = iConnectivityManagerClass.getDeclaredMethod("setMobileDataEnabled", Boolean.TYPE);
                setMobileDataEnabledMethod.setAccessible(true);

                setMobileDataEnabledMethod.invoke(iConnectivityManager, enabled);
            } catch (Exception e) {
                Log.e(TAG, "exception thrown", e);
            }
        }

    }

    /**
     * Gets the number of pages in the SMS based on settings and the length of string
     *
     * @param settings is the settings object to check against
     * @param text     is the text from the message object to be sent
     * @return the number of pages required to hold message
     */
   /* public static int getNumPages(Settings settings, String text) {
        if (settings.getStripUnicode()) {
            text = StripAccents.stripAccents(text);
        }

        int[] data = SmsMessage.calculateLength(text, false);
        return data[0];
    }*/

    /**
     * Gets the current thread_id or creates a new one for the given recipient
     * @param context is the context of the activity or service
     * @param recipient is the person message is being sent to
     * @return the thread_id to use in the database
     */
    public static long getOrCreateThreadId(Context context, String recipient) {
        Set<String> recipients = new HashSet<>();
        recipients.add(recipient);
        return getOrCreateThreadId(context, recipients);
    }

    /**
     * Gets the current thread_id or creates a new one for the given recipient
     * @param context is the context of the activity or service
     * @param recipients is the set of people message is being sent to
     * @return the thread_id to use in the database
     */
    public static long getOrCreateThreadId(Context context, Set<String> recipients) {
        long threadId = getThreadId(context, recipients);
        Random random = new Random();
        return threadId == -1 ? random.nextLong() : threadId;
    }

    /**
     * Gets the current thread_id or -1 if none found
     * @param context is the context of the activity or service
     * @param recipient is the person message is being sent to
     * @return the thread_id to use in the database, -1 if none found
     */
    public static long getThreadId(Context context, String recipient) {
        Set<String> recipients = new HashSet<>();
        recipients.add(recipient);
        return getThreadId(context, recipients);
    }

    /**
     * Gets the current thread_id or -1 if none found
     * @param context is the context of the activity or service
     * @param recipients is the set of people message is being sent to
     * @return the thread_id to use in the database, -1 if none found
     */
    public static long getThreadId(Context context, Set<String> recipients) {
        Uri.Builder uriBuilder = Uri.parse("content://mms-sms/threadID").buildUpon();

        for (String recipient : recipients) {
            if (isEmailAddress(recipient)) {
                recipient = extractAddrSpec(recipient);
            }

            uriBuilder.appendQueryParameter("recipient", recipient);
        }

        Uri uri = uriBuilder.build();
        Cursor cursor = SqliteWrapper.query(context, context.getContentResolver(),
                uri, new String[]{"_id"}, null, null, null);
        if (cursor != null) {
            try {
                if (cursor.moveToFirst()) {
                    return cursor.getLong(0);
                } else {

                }
            } finally {
                cursor.close();
            }
        }

        return -1;
    }

    public static boolean isEmailAddress(String address) {
        if (TextUtils.isEmpty(address)) {
            return false;
        }

        String s = extractAddrSpec(address);
        Matcher match = EMAIL_ADDRESS_PATTERN.matcher(s);
        return match.matches();
    }

    private static final Pattern EMAIL_ADDRESS_PATTERN
            = Pattern.compile(
            "[a-zA-Z0-9\\+\\.\\_\\%\\-]{1,256}" +
                    "\\@" +
                    "[a-zA-Z0-9][a-zA-Z0-9\\-]{0,64}" +
                    "(" +
                    "\\." +
                    "[a-zA-Z0-9][a-zA-Z0-9\\-]{0,25}" +
                    ")+"
    );

    private static final Pattern NAME_ADDR_EMAIL_PATTERN =
            Pattern.compile("\\s*(\"[^\"]*\"|[^<>\"]+)\\s*<([^<>]+)>\\s*");

    public static String extractAddrSpec(String address) {
        Matcher match = NAME_ADDR_EMAIL_PATTERN.matcher(address);

        if (match.matches()) {
            return match.group(2);
        }
        return address;
    }

    /**
     * Gets the default settings from a shared preferences file associated with your app
     * @param context is the context of the activity or service
     * @return the settings object to send with
     */
    /*public static Settings getDefaultSendSettings(Context context) {
        SharedPreferences sharedPrefs = PreferenceManager.getDefaultSharedPreferences(context);
        Settings sendSettings = new Settings();

        sendSettings.setMmsc(sharedPrefs.getString("mmsc_url", ""));
        sendSettings.setProxy(sharedPrefs.getString("mms_proxy", ""));
        sendSettings.setPort(sharedPrefs.getString("mms_port", ""));
        sendSettings.setAgent(sharedPrefs.getString("mms_agent", ""));
        sendSettings.setUserProfileUrl(sharedPrefs.getString("mms_user_agent_profile_url", ""));
        sendSettings.setUaProfTagName(sharedPrefs.getString("mms_user_agent_tag_name", ""));
        sendSettings.setGroup(sharedPrefs.getBoolean("group_message", true));
        sendSettings.setDeliveryReports(sharedPrefs.getBoolean("delivery_reports", false));
        sendSettings.setSplit(sharedPrefs.getBoolean("split_sms", false));
        sendSettings.setSplitCounter(sharedPrefs.getBoolean("split_counter", false));
        sendSettings.setStripUnicode(sharedPrefs.getBoolean("strip_unicode", false));
        sendSettings.setSignature(sharedPrefs.getString("signature", ""));
        sendSettings.setSendLongAsMms(true);
        sendSettings.setSendLongAsMmsAfter(3);
        sendSettings.setAccount(null);
        sendSettings.setRnrSe(null);

        return sendSettings;
    }*/

    /**
     * Determines whether or not the user has Android 4.4 KitKat
     * @return true if version code on device is >= kitkat
     */
    public static boolean hasKitKat() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT;
    }

    /**
     * Determines whether or not the app is the default SMS app on a device
     * @param context
     * @return true if app is default
     */
    public static boolean isDefaultSmsApp(Context context) {
        return !hasKitKat() || context.getPackageName().equals(Telephony.Sms.getDefaultSmsPackage(context));
    }
    
    /**
     * Base columns for tables that contain text-based SMSs.
     */
    public interface TextBasedSmsColumns {

        /** Message type: all messages. */
        public static final int MESSAGE_TYPE_ALL    = 0;

        /** Message type: inbox. */
        public static final int MESSAGE_TYPE_INBOX  = 1;

        /** Message type: sent messages. */
        public static final int MESSAGE_TYPE_SENT   = 2;

        /** Message type: drafts. */
        public static final int MESSAGE_TYPE_DRAFT  = 3;

        /** Message type: outbox. */
        public static final int MESSAGE_TYPE_OUTBOX = 4;

        /** Message type: failed outgoing message. */
        public static final int MESSAGE_TYPE_FAILED = 5;

        /** Message type: queued to send later. */
        public static final int MESSAGE_TYPE_QUEUED = 6;

        /**
         * The type of message.
         * <P>Type: INTEGER</P>
         */
        public static final String TYPE = "type";

        /**
         * The thread ID of the message.
         * <P>Type: INTEGER</P>
         */
        public static final String THREAD_ID = "thread_id";

        /**
         * The address of the other party.
         * <P>Type: TEXT</P>
         */
        public static final String ADDRESS = "address";

        /**
         * The date the message was received.
         * <P>Type: INTEGER (long)</P>
         */
        public static final String DATE = "date";

        /**
         * The date the message was sent.
         * <P>Type: INTEGER (long)</P>
         */
        public static final String DATE_SENT = "date_sent";

        /**
         * Has the message been read?
         * <P>Type: INTEGER (boolean)</P>
         */
        public static final String READ = "read";

        /**
         * Has the message been seen by the user? The "seen" flag determines
         * whether we need to show a notification.
         * <P>Type: INTEGER (boolean)</P>
         */
        public static final String SEEN = "seen";

        /**
         * {@code TP-Status} value for the message, or -1 if no status has been received.
         * <P>Type: INTEGER</P>
         */
        public static final String STATUS = "status";

        /** TP-Status: no status received. */
        public static final int STATUS_NONE = -1;
        /** TP-Status: complete. */
        public static final int STATUS_COMPLETE = 0;
        /** TP-Status: pending. */
        public static final int STATUS_PENDING = 32;
        /** TP-Status: failed. */
        public static final int STATUS_FAILED = 64;

        /**
         * The subject of the message, if present.
         * <P>Type: TEXT</P>
         */
        public static final String SUBJECT = "subject";

        /**
         * The body of the message.
         * <P>Type: TEXT</P>
         */
        public static final String BODY = "body";

        /**
         * The ID of the sender of the conversation, if present.
         * <P>Type: INTEGER (reference to item in {@code content://contacts/people})</P>
         */
        public static final String PERSON = "person";

        /**
         * The protocol identifier code.
         * <P>Type: INTEGER</P>
         */
        public static final String PROTOCOL = "protocol";

        /**
         * Is the {@code TP-Reply-Path} flag set?
         * <P>Type: BOOLEAN</P>
         */
        public static final String REPLY_PATH_PRESENT = "reply_path_present";

        /**
         * The service center (SC) through which to send the message, if present.
         * <P>Type: TEXT</P>
         */
        public static final String SERVICE_CENTER = "service_center";

        /**
         * Is the message locked?
         * <P>Type: INTEGER (boolean)</P>
         */
        public static final String LOCKED = "locked";

        /**
         * The subscription to which the message belongs to. Its value will be
         * < 0 if the sub id cannot be determined.
         * <p>Type: INTEGER (long) </p>
         */
        public static final String SUBSCRIPTION_ID = "sub_id";

        /**
         * The MTU size of the mobile interface to which the APN connected
         * @hide
         */
        public static final String MTU = "mtu";

        /**
         * Error code associated with sending or receiving this message
         * <P>Type: INTEGER</P>
         */
        public static final String ERROR_CODE = "error_code";

        /**
         * The identity of the sender of a sent message. It is
         * usually the package name of the app which sends the message.
         * <p class="note"><strong>Note:</strong>
         * This column is read-only. It is set by the provider and can not be changed by apps.
         * <p>Type: TEXT</p>
         */
        public static final String CREATOR = "creator";
    }
    
    /**
     * Move a message to the given folder.
     *
     * @param context the context to use
     * @param uri the message to move
     * @param folder the folder to move to
     * @return true if the operation succeeded
     * @hide
     */
    public static boolean moveMessageToFolder(Context context,
            Uri uri, int folder, int error) {
        if (uri == null) {
            return false;
        }

        boolean markAsUnread = false;
        boolean markAsRead = false;
        switch(folder) {
        case TextBasedSmsColumns.MESSAGE_TYPE_INBOX:
        case TextBasedSmsColumns.MESSAGE_TYPE_DRAFT:
            break;
        case TextBasedSmsColumns.MESSAGE_TYPE_OUTBOX:
        case TextBasedSmsColumns.MESSAGE_TYPE_SENT:
            markAsRead = true;
            break;
        case TextBasedSmsColumns.MESSAGE_TYPE_FAILED:
        case TextBasedSmsColumns.MESSAGE_TYPE_QUEUED:
            markAsUnread = true;
            break;
        default:
            return false;
        }

        ContentValues values = new ContentValues(3);

        values.put(TextBasedSmsColumns.TYPE, folder);
        if (markAsUnread) {
            values.put(TextBasedSmsColumns.READ, 0);
        } else if (markAsRead) {
            values.put(TextBasedSmsColumns.READ, 1);
        }
        values.put(TextBasedSmsColumns.ERROR_CODE, error);

        return 1 == SqliteWrapper.update(context, context.getContentResolver(),
                        uri, values, null, null);
    }
    
    /**
     * Add an SMS to the given URI with the specified thread ID.
     *
     * @param resolver       the content resolver to use
     * @param uri            the URI to add the message to
     * @param address        the address of the sender
     * @param body           the body of the message
     * @param subject        the pseudo-subject of the message
     * @param date           the timestamp for the message
     * @param read           true if the message has been read, false if not
     * @param deliveryReport true if a delivery report was requested, false if not
     * @param threadId       the thread_id of the message
     * @return the URI for the new message
     * @hide
     */
    public static Uri addMessageToUri(ContentResolver resolver,
                                      Uri uri, String address, String body, String subject,
                                      Long date, boolean read, boolean deliveryReport, long threadId) {
        ContentValues values = new ContentValues(7);

        values.put(Sms.ADDRESS, address);
        if (date != null) {
            values.put(Sms.DATE, date);
        }
        values.put(Sms.READ, read ? Integer.valueOf(1) : Integer.valueOf(0));
        values.put(Sms.SUBJECT, subject);
        values.put(Sms.BODY, body);
        if (deliveryReport) {
            values.put(Sms.STATUS, Sms.STATUS_PENDING);
        }
        if (threadId != -1L) {
            values.put(Sms.THREAD_ID, threadId);
        }
        return resolver.insert(uri, values);
    }
    
    /**
     * Add an SMS to the given URI.
     *
     * @param resolver       the content resolver to use
     * @param uri            the URI to add the message to
     * @param address        the address of the sender
     * @param body           the body of the message
     * @param subject        the pseudo-subject of the message
     * @param date           the timestamp for the message
     * @param read           true if the message has been read, false if not
     * @param deliveryReport true if a delivery report was requested, false if not
     * @return the URI for the new message
     * @hide
     */
    public static Uri addMessageToUri(ContentResolver resolver,
                                      Uri uri, String address, String body, String subject,
                                      Long date, boolean read, boolean deliveryReport) {
        return addMessageToUri(resolver, uri, address, body, subject,
                date, read, deliveryReport, -1L);
    }
    
    /**
     * Message type: all messages.
     */
    public static final int MESSAGE_TYPE_ALL = 0;

    /**
     * Message type: inbox.
     */
    public static final int MESSAGE_TYPE_INBOX = 1;

    /**
     * Message type: sent messages.
     */
    public static final int MESSAGE_TYPE_SENT = 2;

    /**
     * Message type: drafts.
     */
    public static final int MESSAGE_TYPE_DRAFT = 3;

    /**
     * Message type: outbox.
     */
    public static final int MESSAGE_TYPE_OUTBOX = 4;

    /**
     * Message type: failed outgoing message.
     */
    public static final int MESSAGE_TYPE_FAILED = 5;

    /**
     * Message type: queued to send later.
     */
    public static final int MESSAGE_TYPE_QUEUED = 6;
    
    /**
     * Returns true iff the folder (message type) identifies an
     * outgoing message.
     *
     * @hide
     */
    public static boolean isOutgoingFolder(int messageType) {
        return (messageType == MESSAGE_TYPE_FAILED)
                || (messageType == MESSAGE_TYPE_OUTBOX)
                || (messageType == MESSAGE_TYPE_SENT)
                || (messageType == MESSAGE_TYPE_QUEUED);
    }
}

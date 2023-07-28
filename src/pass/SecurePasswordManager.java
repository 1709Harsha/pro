package pass;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class SecurePasswordManager {

    private static final String REGISTERED_USERS_FILE = "registered_users.txt";
    private static final String USERS_FILE = "users.txt";
    private static final Map<String, String> users = new HashMap<>();
    private static final Map<String, AccountInfo> passwordStorage = new HashMap<>();
    private static final Map<String, String> registered_Users = new HashMap<>();
    private static final Scanner scanner = new Scanner(System.in);
    private static final String AES_ALGORITHM = "AES";
    private static final int AES_KEY_SIZE_BITS = 256;
    private static final String MASTER_PASSWORD_SALT = "MySecureSalt";

    public static void main(String[] args) {
        // Load existing user data from the file at program startup
        loadUserDataFromFile();
        loadPasswordDataFromFile();
        loadRegisteredUsersFromFile();
        while (true) {
            System.out.println("Welcome to Password Manager!");
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine();

            switch (choice) {
                case 1:
                    registerUser();
                    break;
                case 2:
                    login();
                    break;
                case 3:
                    System.out.println("Exiting...");
                    System.exit(0);
                    break;
                default:
                    System.out.println("Invalid choice. Try again.");
            }
        }
    }
    private static void loadUserDataFromFile() {
    try (BufferedReader reader = new BufferedReader(new FileReader(USERS_FILE))) {
        String line;
        while ((line = reader.readLine()) != null) {
            String[] parts = line.split("\t");
            if (parts.length == 2) { // Update to check for 2 parts (username, hashedMasterPassword)
                String username = parts[0];
                String hashedMasterPassword = parts[1];
                users.put(username, hashedMasterPassword);
            }
        }
    } catch (IOException e) {
        System.out.println("Error loading user data from file: " + e.getMessage());
    }
}

    private static void loadRegisteredUsersFromFile() {
        try (BufferedReader reader = new BufferedReader(new FileReader(REGISTERED_USERS_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\t");
                if (parts.length == 2) {
                    String username = parts[0];
                    String encryptedMasterPassword = parts[1];
                    registered_Users.put(username, encryptedMasterPassword);
                }
            }
        } catch (IOException e) {
            System.out.println("Error loading registered users data from file: " + e.getMessage());
        }
    }
    private static void registerUser() {
        System.out.println("Enter a username: ");
        String username = scanner.nextLine();
        if (registered_Users.containsKey(username)) { // Corrected variable name
            System.out.println("Username already exists. Try a different one or please login.");
            return;
        }

        System.out.println("Enter a master password: ");
        String masterPassword = scanner.nextLine();

        // Derive the master key using PBKDF2 with a salt
        byte[] masterKey = deriveMasterKey(masterPassword, MASTER_PASSWORD_SALT);
        if (masterKey == null) {
            System.out.println("Error deriving the master key.");
            return;
        }

        // Hash the master password before storing it
        String hashedMasterPassword = hashPassword(masterPassword + MASTER_PASSWORD_SALT);
        registered_Users.put(username, hashedMasterPassword); // Corrected variable name
        System.out.println("User registered successfully!");

        // Save the username and encrypted master key to the registered_users file
        saveRegisteredUserToFile(username, hashedMasterPassword);
    }


  private static byte[] deriveMasterKey(String masterPassword, String salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(masterPassword.toCharArray(), salt.getBytes(), 65536, AES_KEY_SIZE_BITS);
            SecretKeySpec keySpec = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), AES_ALGORITHM);
            return keySpec.getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void saveRegisteredUserToFile(String username, String hashedMasterPassword) {
        // Encrypt the master key before saving it
        String encryptedMasterKey = Base64.getEncoder().encodeToString(hashedMasterPassword.getBytes());

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(REGISTERED_USERS_FILE, true))) {
            writer.write(username + "\t" + encryptedMasterKey);
            writer.newLine();
        } catch (IOException e) {
            System.out.println("Error saving registered user data to file: " + e.getMessage());
        }
    }


 private static void savePasswordDataToFile() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(USERS_FILE))) {
            for (Map.Entry<String, AccountInfo> entry : passwordStorage.entrySet()) {
                String accountName = entry.getKey();
                String encryptedPassword = entry.getValue().getEncryptedPassword();
                writer.write(accountName + "\t" + encryptedPassword);
                writer.newLine();
            }
        } catch (IOException e) {
            System.out.println("Error saving password data to file: " + e.getMessage());
        }
    }


    private static void saveUserDataToFile() {
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(USERS_FILE))) {
        for (Map.Entry<String, String> entry : users.entrySet()) {
            String username = entry.getKey();
            String hashedMasterPassword = entry.getValue();
            writer.write(username + "\t" + hashedMasterPassword);
            writer.newLine();
        }
    } catch (IOException e) {
        System.out.println("Error saving user data to file: " + e.getMessage());
    }
}
    private static void loadPasswordDataFromFile() {
        try (BufferedReader reader = new BufferedReader(new FileReader(USERS_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\t");
                if (parts.length == 2) { // Update to check for 2 parts (accountName, encryptedPassword)
                    String accountName = parts[0];
                    String encryptedPassword = parts[1];
                    passwordStorage.put(accountName, new AccountInfo(accountName, encryptedPassword)); // Update to store AccountInfo object
                }
            }
        } catch (IOException e) {
            System.out.println("Error loading password data from file: " + e.getMessage());
        }
    }

    private static void login() {
        System.out.println("Enter your username: ");
        String username = scanner.nextLine();
        if (!registered_Users.containsKey(username)) { // Check against registered users map
            System.out.println("User not found. Please register first.");
            return;
        }

        System.out.println("Enter your master password: ");
        String masterPassword = scanner.nextLine();

        // Check if the provided master password matches the stored one
        String storedMasterPassword = registered_Users.get(username); // Fetch encrypted master password
        if (hashPassword(masterPassword + MASTER_PASSWORD_SALT).equals(storedMasterPassword)) {
            System.out.println("Login successful!");
            showPasswordMenu(username);
        } else {
            System.out.println("Invalid master password. Login failed or If you new User then Register First.");
        }
    }

    private static void showPasswordMenu(String username) {
        while (true) {
            System.out.println("Password Manager Menu:");
            System.out.println("1. Store Password");
            System.out.println("2. Retrieve Password");
            System.out.println("3. Generate Password");
            System.out.println("4. Logout");
            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine();

            switch (choice) {
                case 1:
                    storePassword(username);
                    break;
                case 2:
                    retrievePassword(username);
                    break;
                case 3:
                    generatePassword();
                    break;
                case 4:
                    System.out.println("Logging out...");
                    return;
                default:
                    System.out.println("Invalid choice. Try again.");
            }
        }
    }

    private static void storePassword(String username) {
    System.out.println("Enter the account name: ");
    String accountName = scanner.nextLine();
    System.out.println("Enter the password: ");
    String password = scanner.nextLine();

    // Encrypt and store the password
    String encryptedPassword = encrypt(password, users.get(username));
    AccountInfo accountInfo = new AccountInfo(accountName, encryptedPassword);
    passwordStorage.put(accountName, accountInfo);
    System.out.println("Password stored successfully!");
    // Save the password data to the file
    savePasswordDataToFile();
}


    private static void retrievePassword(String username) {
        System.out.println("Enter the account name: ");
        String accountName = scanner.nextLine();

        // Check if the account exists in the passwordStorage map
        if (!passwordStorage.containsKey(accountName)) {
            System.out.println("Account not found.");
            return;
        }

        // Decrypt and retrieve the password
        AccountInfo accountInfo = passwordStorage.get(accountName);
        if (accountInfo == null) {
            System.out.println("Password for the account is not available.");
            return;
        }

        String encryptedPassword = accountInfo.getEncryptedPassword();
        try {
            String decryptedPassword = decrypt(encryptedPassword, users.get(username));
            if (decryptedPassword != null) {
                System.out.println("Retrieved password: " + decryptedPassword);
            } else {
                System.out.println("Failed to retrieve the password.");
            }
        } catch (Exception e) {
            System.out.println("Error retrieving the password: " + e.getMessage());
        }
    }

    private static void generatePassword() {
        System.out.print("Enter desired password length: ");
        int length = scanner.nextInt();
        scanner.nextLine();

        System.out.println("Include uppercase letters? (Y/N): ");
        boolean includeUppercase = scanner.nextLine().equalsIgnoreCase("Y");

        System.out.println("Include lowercase letters? (Y/N): ");
        boolean includeLowercase = scanner.nextLine().equalsIgnoreCase("Y");

        System.out.println("Include digits? (Y/N): ");
        boolean includeDigits = scanner.nextLine().equalsIgnoreCase("Y");

        System.out.println("Include special characters? (Y/N): ");
        boolean includeSpecialChars = scanner.nextLine().equalsIgnoreCase("Y");

        String generatedPassword = generateRandomPassword(length, includeUppercase, includeLowercase, includeDigits, includeSpecialChars);
        System.out.println("Generated Password: " + generatedPassword);
    }

    private static String generateRandomPassword(int length, boolean includeUppercase, boolean includeLowercase, boolean includeDigits, boolean includeSpecialChars) {
        String upperCaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lowerCaseChars = "abcdefghijklmnopqrstuvwxyz";
        String digitChars = "0123456789";
        String specialChars = "!@#$%^&*()_-+=[]{}|;:,.<>?";

        StringBuilder validChars = new StringBuilder();
        if (includeUppercase) validChars.append(upperCaseChars);
        if (includeLowercase) validChars.append(lowerCaseChars);
        if (includeDigits) validChars.append(digitChars);
        if (includeSpecialChars) validChars.append(specialChars);

        Random random = new Random();
        char[] password = new char[length];
        for (int i = 0; i < length; i++) {
            password[i] = validChars.charAt(random.nextInt(validChars.length()));
        }

        return new String(password);
    }

    private static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedPassword = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String encrypt(String plaintext, String masterPassword) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(masterPassword.getBytes(), 0, AES_KEY_SIZE_BITS / 8, AES_ALGORITHM);
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String decrypt(String encryptedText, String masterPassword) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(masterPassword.getBytes(), 0, AES_KEY_SIZE_BITS / 8, AES_ALGORITHM);
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    

    private static class AccountInfo {
        private String accountName;
        private String encryptedPassword;

        public AccountInfo(String accountName, String encryptedPassword) {
            this.accountName = accountName;
            this.encryptedPassword = encryptedPassword;
        }

        public String getAccountName() {
            return accountName;
        }

        public String getEncryptedPassword() {
            return encryptedPassword;
        }
    }
}

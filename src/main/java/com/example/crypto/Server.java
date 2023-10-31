package com.example.crypto;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;


public class Server {
    private static final Integer port = 50644;
    private static final Path dir = Path.of("./skbidi");

    public static void main(String[] args) throws IOException {
        Files.createDirectories(dir);
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                Socket client = serverSocket.accept();
                new Thread(() -> {
                    try {
                        while (true) {
                            handle(client);
                        }
                    } catch (Exception e) { /**/ }
                }).start();
            }
        }
    }


    private static void handle(Socket client) throws IOException {
        var inStream = new DataInputStream(client.getInputStream());
        var outStream = new DataOutputStream(client.getOutputStream());
        String name;

        switch (inStream.readInt()) {

            case 0: // upload
                name = inStream.readUTF();
                byte[] tfKey = EncryptionHelper.recvTwoFishKey(inStream, outStream);
                Files.write(dir.resolve(name + "_key"), tfKey);
                byte[] file = new byte[inStream.readInt()];
                inStream.readFully(file);
                Files.write(dir.resolve(name), file);
                break;

            case 1: // list
                File[] files = new File(String.valueOf(dir)).listFiles();
                assert files != null;
                List<String> fileList = Stream.of(files)
                        .filter(File::isFile)
                        .map(File::getName)
                        .filter(fName -> !fName.endsWith("_key"))
                        .toList();
                outStream.writeInt(fileList.size());
                for (String fn : fileList) {
                    outStream.writeUTF(fn);
                }
                break;

            case 2: // download
                name = inStream.readUTF();
                byte[] key = Files.readAllBytes(dir.resolve(name + "_key"));
                EncryptionHelper.sendTwoFishKey(key, inStream, outStream);
                byte[] fileContents = Files.readAllBytes(dir.resolve(name));
                outStream.writeInt(fileContents.length);
                outStream.write(fileContents);
                break;

            default:
                break;

        }
    }
}

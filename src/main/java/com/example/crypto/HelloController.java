package com.example.crypto;

import javafx.collections.FXCollections;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.ProgressBar;
import javafx.stage.FileChooser;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;


public class HelloController {
    private static DataInputStream inStream;
    private static DataOutputStream outStream;


    @FXML
    private ResourceBundle resources;

    @FXML
    private URL location;

    @FXML
    private ListView<String> areaOfFiles;

    @FXML
    private Button getFile;

    @FXML
    private ProgressBar pb;

    @FXML
    private Button reviewDirectoryBtn;

    @FXML
    private Button sendFile;

    @FXML
    private Label status;

    @FXML
    void gayF(ActionEvent event) throws IOException {
        pb.setProgress(0);
        String fileName = areaOfFiles.getSelectionModel().getSelectedItem();
        FileChooser fileChooser = new FileChooser();
        File saveName = fileChooser.showSaveDialog(null);
        if (saveName == null) {
            status.setText("Ошибка");
            return;
        }
        outStream.writeInt(2);
        outStream.writeUTF(fileName);
        byte[] tfKey = EncryptionHelper.recvTwoFishKey(inStream, outStream);
        byte[] fileContents = new byte[inStream.readInt()];
        inStream.readFully(fileContents);
        byte[] fileDec = EncryptionHelper.decryptFile(fileContents, tfKey);
        Files.write(Path.of(saveName.getAbsolutePath()), fileDec);
        pb.setProgress(100);
        status.setText("Готово");
    }

    @FXML
    void reviewDirectory(ActionEvent event) {
        try {
            outStream.writeInt(1);
            int len = inStream.readInt();
            areaOfFiles.getItems().clear();
            List<String> files = new ArrayList<>();
            for (int i = 0; i < len; ++i)
                files.add(inStream.readUTF());
            areaOfFiles.setItems(FXCollections.observableArrayList(files));
        } catch (Exception e) { /**/ }
    }

    @FXML
    void sendF(ActionEvent event) throws IOException {
        pb.setProgress(0);
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showOpenDialog(null);
        if (file == null) {
            status.setText("Ошибка");
            return;
        }
        outStream.writeInt(0);
        outStream.writeUTF(file.getName());
        byte[] key = TwofishAlgorithm.generateKey();
        EncryptionHelper.sendTwoFishKey(key, inStream, outStream);
        byte[] fileContents = Files.readAllBytes(Path.of(file.getAbsolutePath()));
        byte[] fileEnc = EncryptionHelper.encryptFile(fileContents, key);
        outStream.writeInt(fileEnc.length);
        outStream.write(fileEnc);
        pb.setProgress(100);
        status.setText("Готово");
    }

    @FXML
    void initialize() throws IOException {
        Socket sock = new Socket("localhost", 50644);
        inStream = new DataInputStream(sock.getInputStream());
        outStream = new DataOutputStream(sock.getOutputStream());
    }
}
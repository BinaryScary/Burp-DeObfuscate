package burp;

import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class BurpTab {
    private JPanel RootPanel;
    private JButton saveButton;
    private JTextArea replaceField;
    private JScrollPane scroll;

    private IBurpExtenderCallbacks callbacks;

    public String replacements = "";

    public void saveSettings() {
        callbacks.saveExtensionSetting("replacements",replacements);
    }

    public void loadSettings() {
        replacements = callbacks.loadExtensionSetting("replacements");
        if(replacements == null) {
            replacements = "";
        }
        replaceField.setText(replacements);
    }

    public BurpTab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        setupUI();
        loadSettings();

        // token save button
        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                replacements = replaceField.getText();
                saveSettings();
            }
        });
    }

    private void setupUI() {
        RootPanel = new JPanel(new MigLayout());

        RootPanel.add(new JLabel("<html><b>Replacement List:</b><html>"),"wrap");
        replaceField = new JTextArea();
        scroll = new JScrollPane(replaceField);
        scroll.setVerticalScrollBarPolicy ( ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        scroll.setHorizontalScrollBarPolicy ( ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        RootPanel.add(scroll,"wrap");

        saveButton = new JButton("Save");
        RootPanel.add(saveButton,"wrap");
        JLabel label = new JLabel("<html><p>Match/Replace separator is a space</p><html>");
        RootPanel.add(label);


        RootPanel.setVisible(true);
    }

    public JComponent getRootComponent() {
                                       return RootPanel;
                                                        }

}

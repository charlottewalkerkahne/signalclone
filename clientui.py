import sys
import time
import utils
import client
import storage
import os.path
import mimetypes
import appconfig
from PyQt5 import QtWidgets, uic, QtCore, QtGui

MIMETYPES_TO_ICONS = {
    'text/plain': 'text-x-generic',
    'text/html': 'text-html',
    'image/png': 'image-x-generic'
}


CONNECT_TIMEOUT = 2

class ConvoListItem(QtWidgets.QListWidgetItem):
    def __init__(self):
        super(ConvoListItem, self).__init__()
        self.convo_id = None
        self.sorted_recipient_id_list = None
        self.sorted_recipient_name_list = None
        self.convo_name = None
        self.unread_message = False
        self.set_format()
    def set_format(self,updated=False):
        font = QtGui.QFont()
        font.setFamily(u"Fira Sans")
        font.setPointSize(12)
        if updated:
            font.setBold(True)
        self.setFont(font)
        self.setForeground(QtGui.QColor(QtGui.QColorConstants.White))
    def add_recipients(self, recipient_dict):
        self.sorted_recipient_id_list = sorted(list(recipient_dict.values()))
        self.sorted_recipient_name_list = sorted(list(recipient_dict.keys()))
        self.setText(", ".join(self.sorted_recipient_name_list))
    def set_unread(self):
        self.unread_message = True
        self.set_format(updated=True)
    def set_read(self):
        self.unread_message = False
        self.set_format(updated=False)
    def set_name(self, namestring):
        self.convo_name = namestring
        self.setText(self.convo_name)

class MessageListItem(QtWidgets.QListWidgetItem):
    def __init__(self):
        super(MessageListItem, self).__init__()
        self.attachment = None
        self.content = None
        self.timestamp = None
        self.convo_id = None
        self.sent = None
        self.source = None
    def set_format(self):
        font = QtGui.QFont()
        font.setFamily(u"Fira Sans")
        font.setPointSize(12)
        self.setFont(font)
        self.setForeground(QtGui.QColor(QtGui.QColorConstants.White))
    def setAttachment(self, handle, attachment_name):
        theme = get_icon_from_mimetype(os.path.basename(attachment_name))
        msg_icon = QtGui.QIcon.fromTheme(theme)
        self.setText(handle + ":\n" + attachment_name + "\n")
        self.setIcon(msg_icon)
    def setDm(self, dm):
        self.attachment = dm['ATTACHMENT']
        self.content = dm['CONTENT']
        self.timestamp = dm['TIMESTAMP']
        self.convo_id = dm['CONVERSATION_ID']
    def setNiceText(self, handle):
        self.setText(handle + ':\n' + self.content + '\n')
    def updateSent(self):
        pass





def get_icon_from_mimetype(fname):
    mtype = mimetypes.guess_type(fname)
    if mtype[0] in MIMETYPES_TO_ICONS:
        return MIMETYPES_TO_ICONS[mtype[0]]
    else:
        return "text-x-generic"

def load_default_storage():
    storage_path = os.path.join(
        "/tmp/TESTS/",
        "client_0.db"
    )
    return storage.load_storage(storage_path)

class GestureUi(QtWidgets.QMainWindow):
    def __init__(self):
        super(GestureUi, self).__init__()
        uic.loadUi('chatserver.ui', self)
        self.show()

        self.client = None

        self.config = None
        self.load_default_values()

        self.servernameInput.returnPressed.connect(self.verify_servername)
        self.servernameInput.editingFinished.connect(self.verify_servername)

        self.usernameInput.returnPressed.connect(self.verify_username)
        self.usernameInput.editingFinished.connect(self.verify_username)

        self.connectButton.clicked.connect(self.attempt_connect)

        self.newConvoButton.clicked.connect(self.get_convo_participants)

        self.convoAddDialog = QtWidgets.QInputDialog()
        self.convoAddDialog.setLabelText("Comma separated list of recipients: ")
        self.convoAddDialog.accepted.connect(self.create_new_conversation)

        self.activeConversationList.currentRowChanged.connect(self.view_conversation)
        self.activeConversationList.clicked.connect(self.view_conversation)

        self.errorPopup = QtWidgets.QErrorMessage()

        self.chatInput.installEventFilter(self)
        self.chatInput.textChanged.connect(self.resize_input_field)

        self.input_text = {} #convo_id: unsent text

        self.current_convo_id = None

        self.client_thread = None

        self.convo_items = {} #convo_id: index in list
        self.displays = {}

        self.updateTimer = QtCore.QTimer()
        self.updateTimer.setInterval(1)
        self.updateTimer.timeout.connect(self.client_update)


        self.attachmentButton.clicked.connect(self.add_attachment)
        self.attachments = {} #convo_id : [(attachment_name, attachment_data, mtype)]
        self.attachment_labels = {} #convo_id : index
        self.attachmentStack.hide()

        self.chatInput.setFixedHeight(40)

        self.uninitialized_convos = {} #convo_id: convo_item
        self.newConvoButton.hide()

    def resize_input_field(self):
        doc_size = self.chatInput.document().size().toSize()
        if doc_size.height() > 40:
            if doc_size.height() < 150:
                self.chatInput.setFixedHeight(doc_size.height())


    def add_attachment(self):
        if self.current_convo_id is not None:
            attachment_filename = QtWidgets.QFileDialog.getOpenFileName()[0]
            mtype = mimetypes.guess_type(attachment_filename)
            attachment_data = self.client.load_attachment(attachment_filename)
            if attachment_data is not None:
                self.attachmentStack.show()
                fname = os.path.basename(attachment_filename)
                if self.current_convo_id not in self.attachments:
                    new_label = self.create_attachment_label_widget(self.current_convo_id, fname)
                    self.attachmentStack.setCurrentWidget(new_label)
                    new_label.show()
                    self.attachments[self.current_convo_id] = [(attachment_filename, attachment_data, mtype)]
                else:
                    attachment_label_index = self.attachment_labels[self.current_convo_id]
                    attachment_label = self.attachmentStack.widget(attachment_label_index)
                    attachment_label_text = attachment_label.text()
                    attachment_label.show()
                    attachment_label.setText(attachment_label_text + ", " + fname)
                    self.attachments[self.current_convo_id].append((attachment_filename, attachment_data, mtype))

    def fetch_messages(self, conversation_id, new_widget):
        messages = self.client.load_messages(conversation_id)
        for (source_id, message, id, timestamp, attachment_name) in messages:
            msg_item = MessageListItem()
            msg_item.set_format()
            msg_item.source = utils.decode_64(source_id)
            msg_item.content = message
            msg_item.convo_id = conversation_id
            msg_item.timestamp = timestamp
            msg_item.attachment = attachment_name
            handle = self.client.get_username_from_id(msg_item.source)
            if attachment_name is None:
                msg_item.attachment = ""
            if attachment_name != "":
                msg_item.setAttachment(handle, attachment_name)
            else:
                msg_item.setNiceText(handle)
            new_widget.addItem(msg_item)
        return messages

    def load_conversations(self):
        convo_list = self.client.load_conversations()
        for (convo_id, participant_list, name) in convo_list:
            new_convo_list_item = ConvoListItem()
            new_convo_list_item.convo_id = convo_id
            new_convo_list_item.convo_name = name
            participant_dict = {}
            convo_dict = {"peers": [], "messages": []}
            new_widget = self.createChatDisplayWidget(convo_id)
            convo_dict["messages"] = self.fetch_messages(convo_id, new_widget)
            for peer_id in participant_list:
                convo_dict["peers"].append(peer_id)
                self.client.conversations[convo_id] = convo_dict
                participant_dict[self.client.get_username_from_id(peer_id)] = peer_id
            self.client.conversations[convo_id] = convo_dict
            new_convo_list_item.add_recipients(participant_dict)
            self.convo_items[convo_id] = self.activeConversationList.count()
            self.activeConversationList.addItem(new_convo_list_item)


    def client_update(self):
        if self.client is not None:
            self.client.update()
            for new_conversation_id, participant_dict in self.client.new_conversations:
                peers = self.client.conversations[new_conversation_id]["peers"]
                new_convo_item = ConvoListItem()
                new_convo_item.add_recipients(participant_dict)
                new_convo_item.convo_id = new_conversation_id
                self.convo_items[new_conversation_id] = self.activeConversationList.count()
                self.activeConversationList.addItem(new_convo_item)
                self.createChatDisplayWidget(new_conversation_id)
                self.client.save_conversation(new_conversation_id, peers)
            #this should not cause a race condition because the underlying client class
            #is not multithreaded
            self.client.new_conversations = []
            for convo_id,message_list in self.client.new_messages.items():
                for source,dm in message_list:
                    new_message = MessageListItem()
                    new_message.set_format()
                    new_message.attachment = dm["ATTACHMENT"]
                    new_message.content = dm["CONTENT"]
                    new_message.source = source
                    new_message.convo_id = convo_id
                    new_message.timestamp = dm["TIMESTAMP"]
                    if dm["ATTACHMENT"] != "":
                        handle = self.client.get_username_from_id(source)
                        new_message.setAttachment(handle, dm["ATTACHMENT"])
                    else:
                        new_message.setNiceText(self.client.get_username_from_id(source))
                    index = self.displays[convo_id]
                    self.chatHistoryStack.widget(index).addItem(new_message)
                    self.chatHistoryStack.widget(index).scrollToBottom()
                    if convo_id != self.current_convo_id:
                        convo_index = self.convo_items[convo_id]
                        convo_item = self.activeConversationList.item(convo_index)
                        if not convo_item.unread_message:
                            convo_item.set_unread()
            self.client.new_messages = {}


    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.KeyRelease and obj is self.chatInput:
            if event.key() == QtCore.Qt.Key_Return and self.chatInput.hasFocus():
                self.send_message()
                self.chatInput.setFixedHeight(40)
        return super().eventFilter(obj, event)

    def send_message(self):
        message = self.chatInput.toPlainText()
        self.chatInput.clear()
        dm = None

        assert(self.current_convo_id is not None)
        if self.current_convo_id in self.attachments:
            for (attachment_fname, attachment_bytes, mtype) in self.attachments[self.current_convo_id]:
                attachment_dm = self.client.send_dm(self.current_convo_id, attachment_bytes, os.path.basename(attachment_fname))
                attachment, timestamp, content, source_id, convo_id = attachment_dm
                attachment_dm_item = MessageListItem()
                attachment_dm_item.attachment = attachment_fname
                attachment_dm_item.content = content
                attachment_dm_item.timestamp = timestamp
                attachment_dm_item.source = source_id
                attachment_dm_item.convo_id = convo_id
                attachment_dm_item.set_format()
                attachment_dm_item.setAttachment(self.client.handle, os.path.basename(attachment_fname))
                self.chatHistoryStack.currentWidget().addItem(attachment_dm_item)
                self.chatHistoryStack.currentWidget().scrollToBottom()
            del self.attachments[self.current_convo_id]
            attachment_label = self.attachmentStack.widget(self.attachment_labels[self.current_convo_id])
            attachment_label.setText("")
            attachment_label.hide()
            self.attachmentStack.hide()
        if len(message) > 1:
            dm_info = self.client.send_dm(self.current_convo_id, message[:-1])
            attachment, timestamp, content, source_id, convo_id = dm_info
            dm_item = MessageListItem()
            dm_item.set_format()
            dm_item.attachment = attachment
            dm_item.content = content
            dm_item.timestamp = timestamp
            dm_item.convo_id = convo_id
            dm_item.source = source_id
            dm_item.setNiceText(self.client.handle)
            self.chatHistoryStack.currentWidget().addItem(dm_item)
            self.chatHistoryStack.currentWidget().scrollToBottom()



    def unknown_recipients(self, unknown_names):
        unknown_names = " ".join(unknown_names)
        error_message = "The following usernames could not be found in the addressbook: {}".format(unknown_names)
        self.errorPopup.showMessage(error_message)

    def connection_error(self):
        self.errorPopup.showMessage("Failed to connect to remote peer.")

    def create_attachment_label_widget(self, convo_id, filename):
        if convo_id not in self.attachments:
            new_label = QtWidgets.QLabel(filename)
            new_label.setStyleSheet("QLabel {color: white; }")
            new_label.show()
            self.attachmentStack.addWidget(new_label)
            self.attachment_labels[convo_id] = self.attachmentStack.indexOf(new_label)
            return new_label

    def createChatDisplayWidget(self, convo_id):
        new_widget = QtWidgets.QListWidget()
        new_widget.setStyleSheet('border-radius: 10px;\nborder: 3px solid black; background-color: black;')
        new_widget.show()
        new_widget.setEnabled(True)
        new_widget.itemClicked.connect(self.view_message_information)
        new_widget.setWordWrap(True)
        self.chatHistoryStack.addWidget(new_widget)
        self.displays[convo_id] = self.chatHistoryStack.indexOf(new_widget)
        return new_widget

    def view_message_information(self):
        widget = self.chatHistoryStack.currentWidget().currentItem()
        timesent = widget.timestamp
        is_attachment = widget.attachment != "" and widget.attachment is not None
        if is_attachment:
            content = widget.attachment
        else:
            content = widget.content

        source_handle = self.client.get_username_from_id(widget.source)
        source_id = utils.encode_64(widget.source)
        message_info_dialog = QtWidgets.QMessageBox()
        if is_attachment:
            label = "Sender handle {}:\n(id: {})\nTime sent {}\nAttachment: {}\nAttachment Name: \n'{}'".format(
                source_handle,
                source_id,
                time.asctime(time.localtime(timesent)),
                is_attachment,
                content
            )
            message_info_dialog.addButton(QtWidgets.QMessageBox.Save)
        else:
            label = "Sender handle {}:\n(id: {})\nTime sent {}\nAttachment: {}\nMessage Content: \n'{}'".format(
                source_handle,
                source_id,
                time.asctime(time.localtime(timesent)),
                is_attachment,
                content
            )
        message_info_dialog.addButton(QtWidgets.QMessageBox.Ok)
        message_info_dialog.setText(label)
        message_info_dialog.buttonClicked.connect(self.save_file)
        message_info_dialog.exec()

    def save_file(self, button):
        if button.text() == "&OK":
            pass
        elif button.text() == "&Save":
            widget = self.chatHistoryStack.currentWidget().currentItem()
            content = widget.content
            fname = widget.attachment
            if not self.client.save_attachment(content, fname):
                print("Could not save attachment")

    def view_conversation(self):
        convo_item = self.activeConversationList.currentItem()
        convo_item.set_read()
        id = convo_item.convo_id
        self.chatInput.setEnabled(True)
        if self.current_convo_id is not None:
            #save any text in the input box before switching conversations
            self.input_text[self.current_convo_id] = self.chatInput.toPlainText()
            self.chatInput.clear()
        if id in self.input_text:
            #restore any saved text to the input box
            self.chatInput.setText(self.input_text[id])
            del self.input_text[id]
        self.current_convo_id = id
        current_widget = self.chatHistoryStack.widget(self.displays[self.current_convo_id])
        if id in self.attachments:
            self.attachmentStack.show()
            current_label = self.attachmentStack.widget(self.attachment_labels[self.current_convo_id])
            self.attachmentStack.setCurrentWidget(current_label)
        else:
            self.attachmentStack.hide()
        self.chatHistoryStack.setCurrentWidget(current_widget)
        self.chatHistoryStack.currentWidget().scrollToBottom()

    def verify_recipients(self):
        csv_recipients = self.convoAddDialog.textValue()
        #get rid of spaces and then split at commas
        recipient_list = ''.join(csv_recipients.split(' ')).split(',')
        verified_dict = {}
        for recipient in recipient_list:
            verified_dict[recipient] = self.client.get_id_from_username(recipient)
        verified_dict[self.client.handle] = self.client.get_id_from_username(self.client.handle)
        return verified_dict

    def create_new_conversation(self):
        recipients = self.verify_recipients()
        unknown_usernames = []
        for username, id in recipients.items():
            if id is None:
                unknown_usernames.append(username)

        if len(unknown_usernames) > 0:
            self.unknown_recipients(unknown_usernames)
        else:
            new_item = ConvoListItem()
            new_item.add_recipients(recipients)

            new_id = self.client.start_conversation(recipients.keys())
            self.convo_items[new_id] = self.activeConversationList.count()
            self.activeConversationList.addItem(new_item)
            self.client.save_conversation(new_id, recipients.values())
            new_item.convo_id = new_id
            self.createChatDisplayWidget(new_id)

    def get_convo_participants(self):
        self.convoAddDialog.setTextValue("")
        self.convoAddDialog.exec()


    def load_default_values(self):
        self.config = appconfig.load_default_config()
        default_section_name = self.config['DEFAULTSECTION']['section-name']
        default_username = self.config[default_section_name]['Login-Name']
        self.usernameInput.setText(default_username)
        self.servernameInput.setText(default_section_name)

    def verify_username(self):
        pass

    def verify_servername(self):
        self.usernameInput.setFocus()

    def get_server_addr_from_servername(self, servername):
        server_ip = self.config[servername]['Server-Address']
        server_port = self.config[servername]['Server-Port']
        return (server_ip, int(server_port))

    def attempt_connect(self):
        if self.client is None:
            servername = self.servernameInput.text()
            server_addr = self.get_server_addr_from_servername(servername)
            username = self.usernameInput.text()
            new_client = load_client_information(username)
            if new_client is None:
                print("could not load storage for client named {}".format(username))
            else:
                err = new_client.connect_to_server(server_addr)
                if err is None:
                    self.connectionLabel.setStyleSheet("color: yellow")
                    label = "Connecting"
                    count = 0
                    starttime = time.time()
                    while not new_client.handshake_complete():
                        current_time = time.time()
                        time.sleep(.1)
                        label += "."
                        self.connectionLabel.setText(label)
                        self.connectionLabel.repaint()
                        new_client.update()
                        count += 1
                        if count >= 3:
                            count = 0
                            label = "Connecting"
                        if current_time - starttime >= CONNECT_TIMEOUT:
                            break
                    if new_client.handshake_complete():
                        self.connectionLabel.setStyleSheet("color: green")

                        self.client = new_client
                        self.connectionLabel.setText("Connected")
                        self.client.post_prekey_bundle()
                        self.newConvoButton.setEnabled(True)
                        self.usernameInput.setEnabled(False)
                        self.servernameInput.setEnabled(False)
                        self.newConvoButton.show()
                        self.updateTimer.start()
                        self.load_conversations()
                        self.client.fetch_messages_from_server()
                        self.connectButton.setCheckable(True)
                        self.connectButton.setChecked(True)
                    else:
                        self.errorPopup.showMessage(
                            "Remote server seems up but is not letting you login." \
                            "This may be because:\n" \
                            "1) The server thinks you are already connected,\n" \
                            "2) The server does not have your public login key, or\n" \
                            "3) The idiot who coded this messed up.\n\n"\
                        )
                        self.connectionLabel.setText("Disconnected")
                        self.connectionLabel.setStyleSheet("color: red")
                else:
                    print(err)
        else:
            self.client.disconnect()
            self.connectionLabel.setText("Disconnected")
            self.connectionLabel.setStyleSheet("color: red")
            self.newConvoButton.setEnabled(False)
            self.newConvoButton.hide()
            self.usernameInput.setEnabled(True)
            self.servernameInput.setEnabled(True)
            self.activeConversationList.clear()
            self.chatInput.setEnabled(False)
            self.updateTimer.stop()
            self.client = None
            self.connectButton.setCheckable(False)
            self.connectButton.setChecked(False)





def load_client_information(username):
    db_connection = storage.load_storage("/tmp/TESTS/{}.sqlite3".format(username))
    if db_connection is not None:
        new_client = client.get_client(username, db_connection)
        return new_client
    return None

if __name__=="__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = GestureUi()
    app.exec_()
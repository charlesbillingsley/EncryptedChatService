"""
Project 4; A server for an encrypted chat program.
Charles Edward Billingsley
"""

import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

condition = threading.Condition()
current_Users = []
inboxes = {}
keys = {}
flag = 0
public_key = ''
private_key = ''


def generate_keys():
    global public_key, private_key

    """
        Generate Key
    """
    key = RSA.generate(1024)

    """
        Encrypt My Key
    """
    private_key = key.exportKey(pkcs=8, protection="scryptAndAES128-CBC")

    """
        Public Key Creation
    """
    public_key = key.publickey().exportKey()


def encrypt(receivers_public_key, data_to_encrypt):
    # import our public key into a variable
    recipient_key = RSA.import_key(receivers_public_key)

    # create a 16-byte session key
    session_key = get_random_bytes(16)

    # Optimal asymmetric encryption padding allows us to write a data
    # of an arbitrary length
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_data = cipher_rsa.encrypt(session_key)

    # create our AES cipher
    cipher_aes = AES.new(session_key, AES.MODE_EAX)

    # save data to encrypt to variable
    data = data_to_encrypt

    # Encrypt the data. This returns the encrypted text and MAC
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    # Write the nonce, MAC (tag), and encrypted text to the variable
    # a nonce is an arbitrary number that is only used for
    # cryptographic communication. They are usually random or
    # pseudo-random numbers. For AES, it must be at least
    # 16 bytes in length.
    encrypted_data += cipher_aes.nonce
    encrypted_data += tag
    encrypted_data += ciphertext

    return encrypted_data


def decrypt(data_to_decrypt, receiver_private_key):
    # Import our private key
    this_private_key = RSA.import_key(receiver_private_key)

    # Split out the data. The private key is first, then the next 16 bytes
    # for the nonce, which is followed by the next 16 bytes which is the tag
    # and finally the rest of the file, which is our data.
    encrypted_session_key = data_to_decrypt[:this_private_key.size_in_bytes()]
    nonce = data_to_decrypt[
            this_private_key.size_in_bytes():
            this_private_key.size_in_bytes() + 16]
    tag = data_to_decrypt[
          this_private_key.size_in_bytes() + 16:
          this_private_key.size_in_bytes() + 32]
    ciphertext = data_to_decrypt[this_private_key.size_in_bytes() + 32:]

    # Decrypt our session key
    cipher_rsa = PKCS1_OAEP.new(this_private_key)
    try:
        session_key = cipher_rsa.decrypt(encrypted_session_key)

        # Recreate our AES key and decrypt the data
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)

        return data.decode('utf-8')
    except ValueError as ve:
        print("problem with encryption: ", ve)
        print(data_to_decrypt)
        exit(1)


def get_client_data(connection):
    global current_Users
    global flag
    global keys
    should_exit = False
    my_username = ""
    while not should_exit:
        try:
            stay_connected_and_try_again = True
            while stay_connected_and_try_again:
                if my_username != "" and my_username in inboxes:
                    for message in inboxes[my_username]:
                        if type(message['message']) is str:
                            connection.sendall((message['header'] + message[
                                'message']).encode("utf-8"))
                        else:
                            connection.sendall(
                                message['header'].encode('utf-8'))
                            connection.sendall(message['message'])

                        inboxes[my_username].remove(message)
                if my_username != "" and my_username not in current_Users:
                    should_exit = True
                    connection.sendall(
                        "\n~#You've been logged out.".encode("utf-8"))
                    break
                received_data = connection.recv(4096)
                try:
                    received_data = received_data.decode("utf-8")
                except UnicodeDecodeError:
                    received_data = decrypt(received_data, private_key)

                if received_data:
                    if "~update" not in received_data \
                            and 'BEGIN PUBLIC KEY' not in received_data \
                            and 'BEGIN ENCRYPTED PRIVATE KEY' not in \
                                received_data:
                        print("received: " + received_data)
                    if 'BEGIN PUBLIC KEY' in received_data:
                        keys[my_username]['public'] = received_data
                    if 'BEGIN ENCRYPTED PRIVATE KEY' in received_data:
                        keys[my_username]['private'] = received_data

                    if "~" in received_data:
                        if "tell" in received_data:
                            encrypted_message = connection.recv(4096)
                            keep_going = True
                            tell_command = received_data
                            while keep_going:
                                if b'~update' in encrypted_message:
                                    encrypted_message = encrypted_message \
                                        .replace(b'~update', b'')
                                else:
                                    keep_going = False
                            decrypted_message = decrypt(encrypted_message,
                                                        keys[my_username][
                                                            'private'])
                            split_data = received_data.split(":")
                            name_to_send_to = split_data[1]
                            name_sending = split_data[2]

                            if "all" in name_to_send_to:
                                print(
                                    "\nForwarding broadcast from "
                                    + name_sending + " to "
                                    + name_to_send_to)

                                for user_name in inboxes:
                                    this_message = encrypt(
                                        keys[user_name]['public'],
                                        decrypted_message.encode('utf-8'))

                                    inboxes[user_name].append(
                                        {'header': tell_command,
                                         'message': this_message})
                            else:
                                print(
                                    "\nForwarding private message from "
                                    + name_sending + " to "
                                    + name_to_send_to)

                                try:
                                    this_message = encrypt(
                                        keys[name_to_send_to]['public'],
                                        decrypted_message.encode('utf-8'))

                                    inboxes[name_to_send_to].append(
                                        {'header': tell_command,
                                         'message': this_message})
                                except KeyError:
                                    print(name_to_send_to + " doesn't exist")
                                    continue

                        elif received_data == "~users":
                            print(
                                "\nClient has requested a list of users.")
                            keep_checking = True
                            while keep_checking:
                                condition.acquire()
                                if flag == 0:
                                    users = '\n'.join(current_Users)
                                    print("Sending list of connected users.")
                                    connection.sendall(
                                        ("\n~users:" + users).encode("utf-8"))
                                    keep_checking = False
                                else:
                                    condition.wait()
                                condition.release()
                        elif "remove" in received_data:
                            name_to_remove = received_data.split(":")[1]
                            print("\n" + name_to_remove + " is exiting.")
                            keep_checking = True
                            while keep_checking:
                                condition.acquire()
                                if flag == 0:
                                    current_Users.remove(name_to_remove)
                                    try:
                                        if inboxes[my_username]:
                                            del inboxes[my_username]
                                    except KeyError:
                                        pass
                                    keep_checking = False
                                else:
                                    condition.wait()
                                condition.release()
                        elif "kick" in received_data:
                            split_data = received_data.split(":")
                            name_to_remove = split_data[1]
                            name_doing_the_kick = split_data[2]
                            print("\n" + name_to_remove
                                  + " is being kicked out by "
                                  + name_doing_the_kick)
                            keep_checking = True
                            while keep_checking:
                                condition.acquire()
                                if flag == 0:
                                    current_Users.remove(name_to_remove)
                                    del inboxes[name_to_remove]
                                    keep_checking = False
                                else:
                                    condition.wait()
                                condition.release()

                        elif received_data == "~exit":
                            print("\nClient is exiting")
                            del inboxes[my_username]
                            my_username = ""
                            should_exit = True
                            break

                        elif received_data == "~updateRequest":
                            connection.sendall(
                                "\n~updateResponse".encode("utf-8"))

                        elif "~registerName" in received_data:
                            my_username = received_data.split(':')[1]
                            keep_checking = True
                            while keep_checking:
                                condition.acquire()
                                if flag == 0:
                                    if my_username not in current_Users:
                                        current_Users.append(my_username)
                                        inboxes[my_username] = []
                                        keys[my_username] = {}
                                        print("\nRegistered new user "
                                              + my_username)
                                        success_notice = "Name registered"
                                        connection.sendall(
                                            success_notice.encode("utf-8"))
                                        keep_checking = False

                                        print("Sending server public key")
                                        connection.sendall(public_key)
                                    else:
                                        failure_notice = "Name already in use"
                                        connection.sendall(
                                            failure_notice.encode("utf-8"))
                                        keep_checking = False
                                else:
                                    condition.wait()
                                condition.release()
                        else:
                            if "~update" not in received_data:
                                print("Client is sent the following "
                                      "unrecognized data: " + received_data)
            if should_exit:
                connection.shutdown(socket.SHUT_WR)
                break

            connection.shutdown(socket.SHUT_WR)
        except IOError:
            continue


class TcpServer(object):
    def __init__(self, port_number):
        self.port_number = port_number
        self.my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.all_threads = []
        while True:
            try:
                self.my_socket.bind(('', int(self.port_number)))
                break
            except IOError as ioe:
                if ioe.errno == 13:
                    print("You do not have permission to use that port number")
                    self.port_number = input("Please enter a port number: ")
                    continue
                else:
                    print("The following error was found: " + str(ioe))
                    self.port_number = input("Please enter a port number: ")
                    continue
            except ValueError as ve:
                print("There was an issue with the entered port number: "
                      + str(ve))
                self.port_number = input("Please enter a port number: ")
                continue
        generate_keys()

    def listen(self):
        self.my_socket.listen(10)
        while True:
            print("Waiting for connection")
            connection, client_address = self.my_socket.accept()
            print("Client has been connected")
            current_thread = threading.Thread(target=get_client_data,
                                              args=(connection,))
            self.all_threads.append(current_thread)
            current_thread.start()

            for thread in self.all_threads:
                if not thread.isAlive():
                    self.all_threads.remove(thread)
                    thread.join()


if __name__ == "__main__":
    server = TcpServer(9876)
    server.listen()

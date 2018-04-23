import socket
import time
import sys
import threading
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

#
# Project 4; A simple TCP client.
# Charles Billingsley
#

my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
condition = threading.Condition()
flag = 0
all_recv_threads = []
all_cmd_threads = []
all_update_threads = []
should_exit = False
command_active = False
my_username = "No Username"
server_public_key = ''
my_public_key = ''
my_private_key = ''


def generate_keys():
    global my_public_key, my_private_key

    """
        Generate Key
    """
    key = RSA.generate(1024)

    """
        Encrypt My Key
    """
    my_private_key = key.exportKey(pkcs=8, protection="scryptAndAES128-CBC")

    """
        Public Key Creation
    """
    my_public_key = key.publickey().exportKey()


def encrypt(public_key, data_to_encrypt):
    # import our public key into a variable
    recipient_key = RSA.import_key(public_key)

    # create a 16-byte session key
    session_key = get_random_bytes(16)

    # Optimal asymmetric encryption padding allows us to write a data
    # of an arbitrary length
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_data = cipher_rsa.encrypt(session_key)

    # create our AES cipher
    cipher_aes = AES.new(session_key, AES.MODE_EAX)

    # save data to encrypt to variable
    if type(data_to_encrypt) is not bytes:
        data = data_to_encrypt.encode('utf-8')
    else:
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
    session_key = cipher_rsa.decrypt(encrypted_session_key)

    # Recreate our AES key and decrypt the data
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return data.decode('utf-8')


def print_commands():
    print(
        "\n=================================== "
        "COMMANDS "
        "===================================")
    print("~tell @<username or all> <message>        "
          "Sends a message     ")
    print(
        "~users                                   "
        "Prints a list of all users logged in.")
    print("~kick <username>                         "
          "Kicks off another user.")
    print(
        "~commands                                "
        "Prints this list of available commands.")
    print(
        "~exit                                    "
        "Disconnects from the server and exits.")
    print(
        "========================================"
        "========================================\n")


def receive():
    global should_exit, server_public_key
    printed = False
    try:
        this_received_data = my_socket.recv(1024)
        if not this_received_data:
            return

        try:
            this_received_data = this_received_data.decode('utf-8')
        except UnicodeDecodeError:
            this_received_data = decrypt(this_received_data, my_private_key)
            print(
                "\n========================= Message From Unknown Sender "
                "========================")
            print(this_received_data)

        if 'BEGIN PUBLIC KEY' in this_received_data:
            server_public_key = this_received_data
            my_encrypted_private_key = encrypt(server_public_key,
                                               my_private_key)
            my_socket.sendall(my_encrypted_private_key)

        if "~#" in this_received_data:
            print("\nMessage from server: \"" + this_received_data.split('#')[
                1] + "\"\n")
            print("Closing socket")
            my_socket.close()
            keep_checking = True
            while keep_checking:
                condition.acquire()
                if flag == 0:
                    should_exit = True
                    keep_checking = False
                else:
                    condition.wait()
                condition.release()
            return

        if "~users" in this_received_data:
            users_output = this_received_data.split(':')[1]
            print(
                "\n========================= USERS =========================")
            print(users_output.lower())
            print(
                "=========================================================\n")
            printed = True

        if "~tell" in this_received_data:
            message_info = this_received_data.split(':')
            sent_to = message_info[1]
            sent_from = message_info[2]

            new_message = my_socket.recv(1024)
            new_message = decrypt(new_message, my_private_key)

            if "all" in sent_to:
                print(
                    "\n========================= Broadcast From "
                    + sent_from
                    + " =========================")
            else:
                print(
                    "\n========================= From "
                    + sent_from
                    + " =========================")

            print(new_message)
            print(
                "============================================================="
                "======\n")

        if printed:
            print("")

    except UnicodeDecodeError as ude:
        print("Problem receiving data. ", ude)
    except (ConnectionResetError, ConnectionAbortedError):
        print("The connection has been closed.")
        should_exit = True
        return


def run_update():
    global should_exit
    if not should_exit:
        time.sleep(1)
        try:
            my_socket.sendall("~update".encode("utf-8"))
        except OSError:
            print('')
    return


def run_commands():
    global should_exit
    try:
        command_executed = False
        message_sent = False
        skip_send = False
        while not message_sent:
            valid_message_entered = False

            outgoing_message = input("")

            while not valid_message_entered and not command_executed:
                if "~" in outgoing_message:
                    if "~tell " in outgoing_message:
                        split_message = outgoing_message.split(' ')
                        if not split_message[1] or '@' \
                                not in outgoing_message:
                            print("Invalid format. Should be: "
                                  "\n\'~tell @john Hello there\' or "
                                  "\n\'~tell @all Hello world\'")
                            break
                        name_to_send_to = split_message[1][1:].lower()
                        if name_to_send_to == my_username:
                            print("Cannot message yourself.")
                            break
                        if not split_message[2]:
                            print("Message empty.")
                            break
                        print(
                            "Sending message to "
                            + name_to_send_to.lower())
                        message_to_send = " ".join(split_message[2:])
                        message_to_send = encrypt(my_public_key,
                                                  message_to_send)
                        my_socket.sendall(
                            ("~tell:" + name_to_send_to + ':'
                             + my_username + ':').encode("utf-8"))

                        my_socket.sendall(message_to_send)

                        outgoing_message = ""
                        command_executed = True
                        message_sent = True
                    elif outgoing_message == "~users":
                        my_socket.sendall(outgoing_message.encode("utf-8"))
                        outgoing_message = ""
                        command_executed = True
                    elif outgoing_message == "~update":
                        my_socket.sendall(outgoing_message.encode("utf-8"))
                        outgoing_message = ""
                        command_executed = True
                    elif outgoing_message == "~exit":
                        keep_checking = True
                        while keep_checking:
                            condition.acquire()
                            if flag == 0:
                                should_exit = True
                                keep_checking = False
                            else:
                                condition.wait()
                            condition.release()
                        command_executed = True
                        my_socket.sendall(
                            ("~remove:" + my_username).encode("utf-8"))
                        break
                    elif "~kick" in outgoing_message:
                        split_message = outgoing_message.split(' ')
                        if not split_message[1]:
                            print(
                                "Invalid format. "
                                "Should be: \'~kick john\'")
                            break
                        if split_message[1].lower() == my_username:
                            print(
                                "Cannot kick yourself. Please use ~exit "
                                "command.")
                            break
                        print("Kicking out " + split_message[1].lower())
                        my_socket.sendall(("~kick:" + split_message[
                            1].lower() + ':' + my_username).encode(
                            "utf-8"))
                        command_executed = True
                    elif outgoing_message == "~commands":
                        print_commands()
                        command_executed = True
                    else:
                        outgoing_message = input(
                            "Messages must not contain '~'. Try again: ")
                else:
                    print("\nInvalid command. Missing '~'")
                    print_commands()
                    break

            if should_exit:
                print("Disconnecting from server.")
            elif skip_send:
                continue
            else:
                print("")
            message_sent = True
            if should_exit:
                break

    except IOError as ioe:
        print("The following error was found: " + str(ioe))


if __name__ == "__main__":
    connection_Successful = False
    while not connection_Successful:
        complete_Address = ("127.0.0.1", 9876)
        connection_Result = my_socket.connect_ex(complete_Address)
        if connection_Result != 0:
            print("Connection failed. Please double check the following: ")
            print("1. Be sure the entered ip address is valid")
            print("2. Be sure the entered port number is valid")
            print("3. Be sure the server is started")
            print("Starting over...")
        else:
            print("Port opened")
            connection_Successful = True
            user_name_successful = False
            while not user_name_successful:
                name = input("Enter a username: ")
                name = name.lower()
                received_Valid_Name = False
                while not received_Valid_Name:
                    if not name.isalnum():
                        name = input(
                            "Invalid user name. Only numbers and letters "
                            "allowed. Try again: ")
                    else:
                        received_Valid_Name = True
                my_username = name
                my_socket.sendall(("~registerName:" + name).encode("utf-8"))
                received_data = my_socket.recv(1024)
                message = received_data.decode("utf-8")
                if "Name registered" in message:
                    print("Registered " + name + " as username")
                    user_name_successful = True
                elif "Name already in use" in message:
                    print(message + ". Try again...")
                else:
                    print("There was a problem with that name. Try again...")

    generate_keys()
    print_commands()
    my_socket.sendall(my_public_key)
    while not should_exit:
        if len(all_recv_threads) == 0:
            recv_thread = threading.Thread(target=receive)
            all_recv_threads.append(recv_thread)
            recv_thread.start()

        for thread in all_recv_threads:
            if not thread.isAlive():
                all_recv_threads.remove(thread)
                thread.join()

        if len(all_cmd_threads) == 0:
            cmd_thread = threading.Thread(target=run_commands)
            all_cmd_threads.append(cmd_thread)
            cmd_thread.start()

        for thread in all_cmd_threads:
            if not thread.isAlive():
                all_cmd_threads.remove(thread)
                thread.join()

        if len(all_update_threads) == 0:
            update_thread = threading.Thread(target=run_update)
            all_update_threads.append(update_thread)
            update_thread.start()

        for thread in all_update_threads:
            if not thread.isAlive():
                all_update_threads.remove(thread)
                thread.join()

    print("closing socket")
    my_socket.close()
    exit(0)

package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

type MapVal struct {
	Symmetric_decrypt_key []byte
	InvitationUUID        userlib.UUID
	HMAC_key              []byte
}

type OwnMap struct {
	Shared_with     []string
	Invitation_UUID userlib.UUID
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username     string
	Salt         []byte
	Files_Owned  map[userlib.UUID]OwnMap
	Files_Access map[userlib.UUID]MapVal
	// PKEKeyGen() (PKEEncKey, PKEDecKey, err error)
	// DSKeyGen() (DSSignKey, DSVerifyKey, err error)
	// RandomBytes(bytes int) (data []byte)

	MasterKey []byte
	PRSA_key  userlib.PKEDecKey
	Pds_key   userlib.DSSignKey
	UserUUID  userlib.UUID
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}
type RSA_Invite struct {
	IUUID userlib.UUID
	Ikeys []byte //will combine both hmac and symm dk here
	// Invitation_hmac_key []byte
	// Invitation_dk       []byte
}
type Invitation struct {
	File_UUID        userlib.UUID
	File_decrypt_key []byte
	File_HMAC_key    []byte
}

type File_Node struct {
	Contents []byte
	Next     userlib.UUID
}
type File_PTR struct {
	Head userlib.UUID
	Tail userlib.UUID
}
type Verification struct {
	// Argon2Key(password []byte, salt []byte, keyLen uint32) (result []byte)
	// RandomBytes(bytes int) (data []byte)
	Salt           []byte
	HashedPassword []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	//Hash(data []byte) (sum []byte)
	//uuid.FromBytes(b []byte) (uuid UUID, err error)
	if username == "" {
		return nil, errors.New(strings.ToTitle("Invalid Username"))
	}
	u, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	_, found := userlib.DatastoreGet(u)
	if found {
		return nil, errors.New(strings.ToTitle("Username already exists!"))
	}
	var verification_struct Verification
	verification_struct.Salt = userlib.RandomBytes(16)
	verification_struct.HashedPassword = userlib.Argon2Key([]byte(password), verification_struct.Salt, 32)
	marshalled_verification_struct, err := json.Marshal(verification_struct)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(u, marshalled_verification_struct)
	user_uuid, err := uuid.FromBytes(userlib.Hash([]byte(username + password))[:16])
	if err != nil {
		return nil, err
	}

	var user User
	user.Username = username
	user.Salt = userlib.RandomBytes(16)
	user.MasterKey = userlib.Hash([]byte(password + username + password))[:16]
	user.Files_Owned = make(map[userlib.UUID]OwnMap)
	user.Files_Access = make(map[userlib.UUID]MapVal)
	user.UserUUID = user_uuid

	private_ds_key, public_ds_key, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	// userlib.KeystoreSet(name string, value PKEEncKey/DSVerifyKey) (err error)
	err = userlib.KeystoreSet(username+"DS", public_ds_key)
	if err != nil {
		return nil, err
	}
	// PKEKeyGen() (PKEEncKey, PKEDecKey, err error)

	public_RSA_key, private_RSA_key, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+"RSA", public_RSA_key)
	if err != nil {
		return nil, err
	}
	user.PRSA_key = private_RSA_key
	user.Pds_key = private_ds_key
	marshalled_user, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}

	iv := userlib.RandomBytes(16)
	key, err := userlib.HashKDF(user.MasterKey, []byte("symm"+"user"))
	if err != nil {
		return nil, err
	}
	key = key[:16]
	// userlib.DatastoreSet(name UUID, value []byte)
	encrypted_user := userlib.SymEnc(key, iv, marshalled_user)
	hmac_key, err := userlib.HashKDF(user.MasterKey, []byte("hmac"+"user"))
	if err != nil {
		return nil, err
	}
	hmac_key = hmac_key[:16]
	hmac_user, err := userlib.HMACEval(hmac_key, encrypted_user)
	if err != nil {
		return nil, err
	}

	total_user := append(encrypted_user, hmac_user...)

	userlib.DatastoreSet(user_uuid, total_user)
	return &user, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var hashed_username []byte = userlib.Hash([]byte(username))[:16]
	u, err := uuid.FromBytes(hashed_username)
	if err != nil {
		return nil, err
	}
	var verification_struct Verification
	data, found := userlib.DatastoreGet(u)
	if !found {
		return nil, err
	}
	err = json.Unmarshal(data, &verification_struct)
	if err != nil {
		return nil, err
	}

	salt := verification_struct.Salt
	inputted_pwd := userlib.Argon2Key([]byte(password), salt, 32)
	if len(inputted_pwd) != len(verification_struct.HashedPassword) {
		return nil, errors.New(strings.ToTitle("Invalid Password"))
	}

	for i := range inputted_pwd {
		if inputted_pwd[i] != verification_struct.HashedPassword[i] {
			return nil, errors.New(strings.ToTitle("Invalid Password"))
		}
	}
	user_uuid, err := uuid.FromBytes(userlib.Hash([]byte(username + password))[:16])
	if err != nil {
		return nil, err
	}
	encrypted_total_user, found := userlib.DatastoreGet(user_uuid)
	if !found {
		return nil, errors.New(strings.ToTitle("Couldn't find user"))
	}
	if len(encrypted_total_user) <= 65 {
		return nil, errors.New(strings.ToTitle("User data has been tampered with"))
	}

	encrypted_user := encrypted_total_user[:len(encrypted_total_user)-64]
	hmac_user := encrypted_total_user[len(encrypted_total_user)-64:]
	master_key := userlib.Hash([]byte(password + username + password))[:16]

	hmac_key, err := userlib.HashKDF(master_key, []byte("hmac"+"user"))
	if err != nil {
		return nil, err
	}
	hmac_key = hmac_key[:16]
	to_verify, err := userlib.HMACEval(hmac_key, encrypted_user)
	if !userlib.HMACEqual(to_verify, hmac_user) {
		return nil, errors.New(strings.ToTitle("User data has been tampered with: HmacEqual failed"))
	}
	key, err := userlib.HashKDF(master_key, []byte("symm"+"user"))
	if err != nil {
		return nil, err
	}
	key = key[:16]

	marshalled_user := userlib.SymDec(key, encrypted_user)
	var ret_user User
	err = json.Unmarshal(marshalled_user, &ret_user)
	if err != nil {
		return nil, err
	}
	return &ret_user, nil

}

func GetFilePtrOwner(File_PTR_uuid userlib.UUID, file_decrypt_key []byte, hmac_key []byte) (ret File_PTR, err error) {
	total_file_ptr, ok := userlib.DatastoreGet(File_PTR_uuid)
	var file_ptr File_PTR
	if !ok {
		return
	}
	integrity, err := CheckNodeIntegrity(hmac_key, total_file_ptr)
	if err != nil {
		return file_ptr, err
	}
	if !integrity {
		return file_ptr, errors.New(strings.ToTitle("File ptr has been tampered with"))
	}
	encrypted_file_ptr := total_file_ptr[:len(total_file_ptr)-64]
	marshalled_file_ptr := userlib.SymDec(file_decrypt_key, encrypted_file_ptr)

	err = json.Unmarshal(marshalled_file_ptr, &file_ptr)
	if err != nil {
		return
	}
	return file_ptr, nil
}

func GetFilePtr(userdata *User, File_PTR_local userlib.UUID) (res File_PTR, dk []byte, hkey []byte, File_PTR_uuid userlib.UUID, err error) {
	buffer_uuid := uuid.Nil
	mapval := userdata.Files_Access[File_PTR_local]
	symm_decrypt_key := mapval.Symmetric_decrypt_key
	invitation_uuid := mapval.InvitationUUID
	invitation_hmac_key := mapval.HMAC_key
	var file_ptr File_PTR
	//first i need to check the integrity of the invitation struct itself
	total_invitation_struct, ok := userlib.DatastoreGet(invitation_uuid)
	if !ok {
		return file_ptr, nil, nil, buffer_uuid, errors.New(strings.ToTitle("Trouble finding invitation struct HERE..."))
	}

	integrity, err := CheckNodeIntegrity(invitation_hmac_key, total_invitation_struct)
	if err != nil {
		return file_ptr, nil, nil, buffer_uuid, err
	}
	if !integrity {
		return file_ptr, nil, nil, buffer_uuid, errors.New(strings.ToTitle("User's mapval has been tampered with"))
	}

	encrypted_invitation_struct := total_invitation_struct[:len(total_invitation_struct)-64]
	marshalled_invitation_struct := userlib.SymDec(symm_decrypt_key, encrypted_invitation_struct)

	var invitation_struct Invitation
	err = json.Unmarshal(marshalled_invitation_struct, &invitation_struct)
	if err != nil {
		return file_ptr, nil, nil, buffer_uuid, err
	}

	total_file_ptr, ok := userlib.DatastoreGet(invitation_struct.File_UUID)
	if !ok {
		return file_ptr, nil, nil, buffer_uuid, errors.New(strings.ToTitle("Trouble finding file ptr..."))
	}
	file_dk := invitation_struct.File_decrypt_key
	file_hmac_key := invitation_struct.File_HMAC_key

	encrypted_file_ptr := total_file_ptr[:len(total_file_ptr)-64]
	integrity, err = CheckNodeIntegrity(file_hmac_key, total_file_ptr)
	if err != nil {
		return file_ptr, nil, nil, buffer_uuid, err
	}
	if !integrity {
		return file_ptr, nil, nil, buffer_uuid, errors.New(strings.ToTitle("file ptr has been tampered with"))
	}

	marshalled_file_ptr := userlib.SymDec(file_dk, encrypted_file_ptr)

	var ret_file_ptr File_PTR
	err = json.Unmarshal(marshalled_file_ptr, &ret_file_ptr)
	if err != nil {

		return file_ptr, nil, nil, buffer_uuid, err
	}
	return ret_file_ptr, file_dk, file_hmac_key, invitation_struct.File_UUID, nil
}

func CreateInvitationStruct(filename string, userdata *User, recipient string) (err error) {
	//only an owner can do this!
	File_PTR_local, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	// storage key points to the file head
	if err != nil {
		return err
	}
	hmac_key, err := userlib.HashKDF(userdata.MasterKey, []byte("hmac_key"+filename))
	if err != nil {
		return err
	}
	hmac_key = hmac_key[:16]
	symm_decrypt_key, err := userlib.HashKDF(userdata.MasterKey, []byte(filename))
	if err != nil {
		return err
	}
	symm_decrypt_key = symm_decrypt_key[:16]

	var invitation Invitation
	invitation.File_HMAC_key = hmac_key
	invitation.File_UUID = File_PTR_local
	invitation.File_decrypt_key = symm_decrypt_key

	marshalled_invitation, err := json.Marshal(invitation)
	if err != nil {
		return err
	}
	symm_decrypt_invitation_key, err := userlib.HashKDF(userdata.MasterKey, []byte(filename+"symm"+"share"+recipient))
	if err != nil {
		return err
	}
	symm_decrypt_invitation_key = symm_decrypt_invitation_key[:16]
	iv := userlib.RandomBytes(16)
	encrypted_invitation := userlib.SymEnc(symm_decrypt_invitation_key, iv, marshalled_invitation)
	hmac_invitation_key, err := userlib.HashKDF(userdata.MasterKey, []byte(filename+"hmac"+"share"+recipient))
	if err != nil {
		return err
	}
	hmac_invitation_key = hmac_invitation_key[:16]
	hmac_invitation, err := userlib.HMACEval(hmac_invitation_key, encrypted_invitation)
	if err != nil {
		return err
	}
	total_invitation := append(encrypted_invitation, hmac_invitation...)

	invitation_uuid := uuid.New()
	var ownMap OwnMap
	ownMap.Invitation_UUID = invitation_uuid
	ownMap.Shared_with = []string{}
	ownMap.Shared_with = append(ownMap.Shared_with, recipient)
	userdata.Files_Owned[File_PTR_local] = ownMap

	UpdateUser(userdata)
	userlib.DatastoreSet(invitation_uuid, total_invitation)

	return nil
}

func GetUpdatedUser(userdata *User) (new_user *User, err error) {
	encrypted_total_user, found := userlib.DatastoreGet(userdata.UserUUID)
	if !found {
		return nil, errors.New(strings.ToTitle("Couldn't find user"))
	}
	if len(encrypted_total_user) <= 65 {
		return nil, errors.New(strings.ToTitle("User data has been tampered with"))
	}
	encrypted_user := encrypted_total_user[:len(encrypted_total_user)-64]
	hmac_user := encrypted_total_user[len(encrypted_total_user)-64:]

	hmac_key, err := userlib.HashKDF(userdata.MasterKey, []byte("hmac"+"user"))
	if err != nil {
		return nil, err
	}
	hmac_key = hmac_key[:16]
	to_verify, err := userlib.HMACEval(hmac_key, encrypted_user)
	if !userlib.HMACEqual(to_verify, hmac_user) {
		return nil, errors.New(strings.ToTitle("User data has been tampered with: HmacEqual failed"))
	}

	symm_key, err := userlib.HashKDF(userdata.MasterKey, []byte("symm"+"user"))
	if err != nil {
		return nil, err
	}
	symm_key = symm_key[:16]
	marshalled_user := userlib.SymDec(symm_key, encrypted_user)
	var ret_user User
	err = json.Unmarshal(marshalled_user, &ret_user)
	if err != nil {
		return nil, err
	}
	return &ret_user, nil

}

func UpdateUser(userdata *User) (err error) {
	marshalled_user, err := json.Marshal(userdata)
	if err != nil {
		return err
	}
	iv := userlib.RandomBytes(16)
	key, err := userlib.HashKDF(userdata.MasterKey, []byte("symm"+"user"))
	if err != nil {
		return err
	}
	key = key[:16]
	// userlib.DatastoreSet(name UUID, value []byte)
	encrypted_user := userlib.SymEnc(key, iv, marshalled_user)
	hmac_key_user, err := userlib.HashKDF(userdata.MasterKey, []byte("hmac"+"user"))
	if err != nil {
		return err
	}
	hmac_key_user = hmac_key_user[:16]
	hmac_user, err := userlib.HMACEval(hmac_key_user, encrypted_user)
	if err != nil {
		return err
	}

	total_user := append(encrypted_user, hmac_user...)

	userlib.DatastoreSet(userdata.UserUUID, total_user)
	return nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	userdata, err = GetUpdatedUser(userdata)
	if err != nil {
		return err
	}

	File_PTR_local, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	// storage key points to the file head
	if err != nil {
		return err
	}

	_, okOwn := userdata.Files_Owned[File_PTR_local]
	_, okAccess := userdata.Files_Access[File_PTR_local]

	if !okOwn && !okAccess {

		var new_File_PTR File_PTR
		new_File_PTR.Head = uuid.New()
		new_File_PTR.Tail = uuid.New()

		var new_file_node File_Node
		new_file_node.Contents = content
		new_file_node.Next = new_File_PTR.Tail

		new_file_node_uuid := new_File_PTR.Head

		symm_decrypt_key, err := userlib.HashKDF(userdata.MasterKey, []byte(filename))
		if err != nil {
			return err
		}
		symm_decrypt_key = symm_decrypt_key[:16]

		marshalled_file_ptr, err := json.Marshal(new_File_PTR)
		if err != nil {
			return err
		}
		marshalled_node, err := json.Marshal(new_file_node)
		if err != nil {
			return err
		}
		iv := userlib.RandomBytes(16)
		encrypted_PTR := userlib.SymEnc(symm_decrypt_key, iv, marshalled_file_ptr)
		encrypted_node := userlib.SymEnc(symm_decrypt_key, iv, marshalled_node)

		hmac_key, err := userlib.HashKDF(userdata.MasterKey, []byte("hmac_key"+filename))
		if err != nil {
			return err
		}
		hmac_key = hmac_key[:16]
		hmac_file_ptr, err := userlib.HMACEval(hmac_key, encrypted_PTR)
		if err != nil {
			return err
		}
		hmac_file_node, err := userlib.HMACEval(hmac_key, encrypted_node)
		if err != nil {
			return err
		}
		total_ptr := append(encrypted_PTR, hmac_file_ptr...)
		total_node := append(encrypted_node, hmac_file_node...)

		userlib.DatastoreSet(File_PTR_local, total_ptr)
		userlib.DatastoreSet(new_file_node_uuid, total_node)

		buffer_uuid := uuid.Nil

		var ownMap OwnMap
		ownMap.Invitation_UUID = buffer_uuid
		ownMap.Shared_with = []string{}
		userdata.Files_Owned[File_PTR_local] = ownMap

		UpdateUser(userdata)

	} else if okOwn {
		//owner of the file but file is already created!
		//therefore, all we need to do is decyrpt the file and change the stuff inside and re-encrypt

		symm_decrypt_key, err := userlib.HashKDF(userdata.MasterKey, []byte(filename))
		if err != nil {
			return err
		}
		symm_decrypt_key = symm_decrypt_key[:16]
		hmac_key, err := userlib.HashKDF(userdata.MasterKey, []byte("hmac_key"+filename))
		if err != nil {
			return err
		}
		hmac_key = hmac_key[:16]
		total_file_ptr, found := userlib.DatastoreGet(File_PTR_local)
		if !found {
			return errors.New(strings.ToTitle("Couldn't find file PTR"))
		}
		integrity, err := CheckNodeIntegrity(hmac_key, total_file_ptr)
		if err != nil {
			return err
		}
		if !integrity {
			return errors.New(strings.ToTitle("File ptr has been tampered with..."))
		}
		encrypted_file_ptr := total_file_ptr[:len(total_file_ptr)-64]

		marshalled_File_PTR := userlib.SymDec(symm_decrypt_key, encrypted_file_ptr)
		var file_ptr File_PTR
		err = json.Unmarshal(marshalled_File_PTR, &file_ptr)
		if err != nil {
			return err
		}

		var new_file_node File_Node
		new_file_node.Contents = content
		new_file_node.Next = uuid.New()

		err = AddNode(new_file_node, file_ptr, symm_decrypt_key, hmac_key)
		if err != nil {
			return err
		}

		err = UpdateFilePtrTail(hmac_key, file_ptr, symm_decrypt_key, new_file_node.Next, File_PTR_local)
		if err != nil {
			return err
		}

		//we created a new struct with contents and we overwrote the stuff that we previously at the file ptr Head with this struct
	} else { //user has only has ACCESS

		file_ptr, file_decrypt_key, hmac_key, File_PTR_uuid, err := GetFilePtr(userdata, File_PTR_local)
		if err != nil {
			return err
		}
		total_file_ptr, found := userlib.DatastoreGet(File_PTR_uuid)
		if !found {
			return errors.New(strings.ToTitle("Couldn't find file PTR"))
		}
		integrity, err := CheckNodeIntegrity(hmac_key, total_file_ptr)
		if err != nil {
			return err
		}
		if !integrity {
			return errors.New(strings.ToTitle("File ptr has been tampered with..."))
		}
		var new_file_node File_Node
		new_file_node.Contents = content
		new_file_node.Next = uuid.New()

		err = AddNode(new_file_node, file_ptr, file_decrypt_key, hmac_key)
		if err != nil {
			return err
		}
		err = UpdateFilePtrTail(hmac_key, file_ptr, file_decrypt_key, new_file_node.Next, File_PTR_uuid)
		if err != nil {
			return err
		}
	}
	return nil
}

func AddNode(new_file_node File_Node, file_ptr File_PTR, file_decrypt_key []byte, hmac_key []byte) (err error) {
	marshalled_file_node, err := json.Marshal(new_file_node)
	iv := userlib.RandomBytes(16)
	encrypted_file_node := userlib.SymEnc(file_decrypt_key, iv, marshalled_file_node)
	if err != nil {
		return err
	}
	hmac_file_node, err := userlib.HMACEval(hmac_key, encrypted_file_node)
	if err != nil {
		return err
	}
	total_file_node := append(encrypted_file_node, hmac_file_node...)
	userlib.DatastoreSet(file_ptr.Tail, total_file_node)
	return nil
}

func UpdateFilePtrTail(hmac_key []byte, file_ptr File_PTR, file_decrypt_key []byte, new_uuid userlib.UUID, File_PTR_uuid userlib.UUID) (err error) {
	file_ptr.Tail = new_uuid //update the tail pointer
	marshalled_file_ptr, err := json.Marshal(file_ptr)
	if err != nil {
		return err
	}
	iv := userlib.RandomBytes(16)
	encypted_file_ptr := userlib.SymEnc(file_decrypt_key, iv, marshalled_file_ptr)
	hmac_file_ptr, err := userlib.HMACEval(hmac_key, encypted_file_ptr)
	if err != nil {
		return err
	}
	total_ptr := append(encypted_file_ptr, hmac_file_ptr...)
	userlib.DatastoreSet(File_PTR_uuid, total_ptr)
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	var err error
	if err != nil {
		return err
	}
	userdata, err = GetUpdatedUser(userdata)
	if err != nil {
		return err
	}

	file_ptr, file_decrypt_key, hmac_key, File_PTR_uuid, err := GetFilePtrMaster(userdata, filename)
	if err != nil {
		return err
	}

	var new_file_node File_Node
	new_file_node.Contents = content
	new_file_node.Next = uuid.New()

	err = AddNode(new_file_node, file_ptr, file_decrypt_key, hmac_key)

	if err != nil {
		return err
	}

	//now i need to marshall and re-encrypt the file-ptr
	err = UpdateFilePtrTail(hmac_key, file_ptr, file_decrypt_key, new_file_node.Next, File_PTR_uuid)
	if err != nil {
		return err
	}
	return nil
}
func GetFilePtrMaster(userdata *User, filename string) (ptr File_PTR, dk []byte, hkey []byte, file_ptr_uuid userlib.UUID, err error) {
	File_PTR_local, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	var File_PTR_uuid userlib.UUID
	buffer_uuid := uuid.Nil
	var file_ptr File_PTR
	if err != nil {
		return file_ptr, nil, nil, buffer_uuid, errors.New(strings.ToTitle("troubling computing uuid!"))
	}
	_, okOwn := userdata.Files_Owned[File_PTR_local]
	_, okAccess := userdata.Files_Access[File_PTR_local]
	if !okOwn && !okAccess {
		return file_ptr, nil, nil, buffer_uuid, errors.New(strings.ToTitle("File not Found in Namespace!"))
	}

	var file_decrypt_key []byte
	var hmac_key []byte
	if okOwn {
		File_PTR_uuid = File_PTR_local
		file_decrypt_key, err = userlib.HashKDF(userdata.MasterKey, []byte(filename))
		if err != nil {
			return file_ptr, nil, nil, buffer_uuid, err
		}
		file_decrypt_key = file_decrypt_key[:16]
		hmac_key, err = userlib.HashKDF(userdata.MasterKey, []byte("hmac_key"+filename))
		hmac_key = hmac_key[:16]
		file_ptr, err = GetFilePtrOwner(File_PTR_local, file_decrypt_key, hmac_key)

		if err != nil {
			return file_ptr, nil, nil, buffer_uuid, err
		}

	} else {

		file_ptr, file_decrypt_key, hmac_key, File_PTR_uuid, err = GetFilePtr(userdata, File_PTR_local)
		if err != nil {
			return file_ptr, nil, nil, buffer_uuid, err
		}
	}
	return file_ptr, file_decrypt_key, hmac_key, File_PTR_uuid, nil

}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	userdata, err = GetUpdatedUser(userdata)
	if err != nil {
		return nil, err
	}
	file_ptr, file_decrypt_key, hmac_key, _, err := GetFilePtrMaster(userdata, filename)
	if err != nil {
		return nil, err
	}
	file_head_node := file_ptr.Head
	contents := []byte("")
	for file_head_node != file_ptr.Tail {
		curr_contents, next, err := GetNode(file_head_node, file_decrypt_key, hmac_key)
		if err != nil {
			return nil, err
		}

		contents = append(contents, curr_contents...)
		file_head_node = next
	}
	return contents, nil
}

func CheckNodeIntegrity(hmac_key []byte, total_node []byte) (ret bool, err error) {
	if len(total_node) < 65 {
		return false, errors.New(strings.ToTitle("Invitation struct has been tampered with. Either user is revoked or malicious activity has occurred..."))
	}
	encrypted_node := total_node[:len(total_node)-64]
	hmac_total_node := total_node[len(total_node)-64:]
	hmac_val, err := userlib.HMACEval(hmac_key, encrypted_node)
	if err != nil {
		return false, errors.New(strings.ToTitle("Recipient username doesn't exist :( "))
	}
	return userlib.HMACEqual(hmac_total_node, hmac_val), nil

}

func GetNode(node_uuid userlib.UUID, decrypt_key []byte, hmac_key []byte) (content []byte, next userlib.UUID, err error) {
	total_node, ok := userlib.DatastoreGet(node_uuid)
	random_uuid := uuid.New()
	if !ok {
		return nil, random_uuid, errors.New(strings.ToTitle("Couldn't retrieve file node"))
	}
	integrity, err := CheckNodeIntegrity(hmac_key, total_node)
	if err != nil {
		return nil, random_uuid, err
	}
	if !integrity {
		return nil, random_uuid, errors.New(strings.ToTitle("Node has been tampered with"))
	}
	encrypted_node := total_node[:len(total_node)-64]
	marshalled_node := userlib.SymDec(decrypt_key, encrypted_node)
	var node File_Node
	err = json.Unmarshal(marshalled_node, &node)
	if err != nil {
		return nil, random_uuid, err
	}
	return node.Contents, node.Next, nil

}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	buffer_uuid := uuid.Nil

	userdata, err = GetUpdatedUser(userdata)
	if err != nil {
		return buffer_uuid, err
	}

	File_PTR_local, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return buffer_uuid, err
	}
	recipient_RSA_key, found := userlib.KeystoreGet(recipientUsername + "RSA")

	if !found {
		return buffer_uuid, errors.New(strings.ToTitle("Recipient username doesn't exist :( "))
	}
	_, okOwn := userdata.Files_Owned[File_PTR_local]
	mapVal, okAccess := userdata.Files_Access[File_PTR_local]
	if !okOwn && !okAccess {
		return buffer_uuid, errors.New(strings.ToTitle("User doesn't have sharing priveldges!"))
	} else if okOwn {
		//undefined behavior: creating invite to someone who already has access/or been revoked
		err := CreateInvitationStruct(filename, userdata, recipientUsername)
		if err != nil {
			return buffer_uuid, err
		}

		invitation_struct_uuid := userdata.Files_Owned[File_PTR_local].Invitation_UUID

		symm_decrypt_invitation_key, err := userlib.HashKDF(userdata.MasterKey, []byte(filename+"symm"+"share"+recipientUsername))
		if err != nil {
			return buffer_uuid, err
		}
		symm_decrypt_invitation_key = symm_decrypt_invitation_key[:16]
		hmac_invitation_key, err := userlib.HashKDF(userdata.MasterKey, []byte(filename+"hmac"+"share"+recipientUsername))
		if err != nil {
			return buffer_uuid, err
		}
		hmac_invitation_key = hmac_invitation_key[:16]

		//now i need to create an RSA struct
		var rsa_invite RSA_Invite
		rsa_invite.IUUID = invitation_struct_uuid
		rsa_invite.Ikeys = append(symm_decrypt_invitation_key, hmac_invitation_key...)
		// rsa_invite.Invitation_dk = symm_decrypt_invitation_key
		// rsa_invite.Invitation_hmac_key = hmac_invitation_key
		marshalled_rsa_invite, err := json.Marshal(rsa_invite)
		if err != nil {
			return buffer_uuid, err
		}

		encrypted_rsa_invite, err := userlib.PKEEnc(recipient_RSA_key, marshalled_rsa_invite)
		// DSSign(sk DSSignKey, msg []byte) (sig []byte, err error)
		if err != nil {
			return buffer_uuid, err
		}

		digital_sig, err := userlib.DSSign(userdata.Pds_key, encrypted_rsa_invite)
		if err != nil {
			return buffer_uuid, err
		}
		total_rsa := append(encrypted_rsa_invite, digital_sig...)
		rsa_invite_uuid := uuid.New()
		userlib.DatastoreSet(rsa_invite_uuid, total_rsa)
		return rsa_invite_uuid, nil
	} else {

		var rsa_invite RSA_Invite
		rsa_invite.IUUID = mapVal.InvitationUUID
		rsa_invite.Ikeys = append(mapVal.Symmetric_decrypt_key, mapVal.HMAC_key...)

		// rsa_invite.Invitation_dk = mapVal.Symmetric_decrypt_key
		// rsa_invite.Invitation_hmac_key = mapVal.HMAC_key

		marshalled_rsa_invite, err := json.Marshal(rsa_invite)
		if err != nil {
			return buffer_uuid, err
		}
		encrypted_rsa_invite, err := userlib.PKEEnc(recipient_RSA_key, marshalled_rsa_invite)
		if err != nil {
			return buffer_uuid, err
		}

		digital_sig, err := userlib.DSSign(userdata.Pds_key, encrypted_rsa_invite)
		if err != nil {
			return buffer_uuid, err
		}
		total_rsa := append(encrypted_rsa_invite, digital_sig...)
		rsa_invite_uuid := uuid.New()
		userlib.DatastoreSet(rsa_invite_uuid, total_rsa)
		return rsa_invite_uuid, nil
	}
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	var err error
	userdata, err = GetUpdatedUser(userdata)
	if err != nil {

		return err
	}
	File_PTR_uuid, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {

		return err
	}
	_, okOwn := userdata.Files_Owned[File_PTR_uuid]
	_, okAccess := userdata.Files_Access[File_PTR_uuid]
	if okOwn || okAccess {
		return errors.New(strings.ToTitle("Filename already exists in namespace"))
	}
	total_rsa, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New(strings.ToTitle("Trouble retrieving rsa struct from DS"))
	}
	// DSVerify(vk DSVerifyKey, msg []byte, sig []byte) (err error)
	// Uses the RSA public (verification) key vk to verify that the signature sig on the message msg is valid. If the signature is valid, err is nil; otherwise, err is not nil.
	public_ds_key, ok := userlib.KeystoreGet(senderUsername + "DS")
	if !ok {
		return errors.New(strings.ToTitle("Sender's public DS key not found"))
	}
	sig := total_rsa[len(total_rsa)-256:]
	encrypted_invite := total_rsa[:len(total_rsa)-256]
	err = userlib.DSVerify(public_ds_key, encrypted_invite, sig)
	if err != nil {
		return err
	}
	//authenticated, now we can actaully decrypt the rsa encrypted struct
	marshalled_invite, err := userlib.PKEDec(userdata.PRSA_key, encrypted_invite)
	if err != nil {
		return err
	}
	var rsa_invite RSA_Invite
	err = json.Unmarshal(marshalled_invite, &rsa_invite)
	if err != nil {
		return err
	}
	total_invite, ok := userlib.DatastoreGet(rsa_invite.IUUID)
	if !ok {
		return errors.New(strings.ToTitle("Trouble retrieving invitation struct from DS"))
	}

	/// do i need to check the integrity of the invitation struct?
	invitation_symm_key := rsa_invite.Ikeys[:16]
	invitation_hmac_key := rsa_invite.Ikeys[16:]
	integrity, err := CheckNodeIntegrity(invitation_hmac_key, total_invite)
	if err != nil {

		return err
	}
	if !integrity {
		return errors.New(strings.ToTitle("Invitation struct has been tampered with"))
	}

	var mapVal MapVal
	mapVal.HMAC_key = invitation_hmac_key
	mapVal.InvitationUUID = rsa_invite.IUUID
	mapVal.Symmetric_decrypt_key = invitation_symm_key
	userdata.Files_Access[File_PTR_uuid] = mapVal
	UpdateUser(userdata)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	/*
		the idea here is that since each subtree shares the same invitation struct, if i just change the values in that invitation struct then they would have no way to decrypt the necessary information
	*/
	var err error
	userdata, err = GetUpdatedUser(userdata)
	if err != nil {
		return err
	}
	File_PTR_local, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	ownMap, okOwn := userdata.Files_Owned[File_PTR_local]
	if !okOwn {
		return errors.New(strings.ToTitle("Trying to revoke access yet file isn't in namespace of user or user isn't owner of file..."))
	}
	shared_with := ownMap.Shared_with
	seen := false
	for _, user := range shared_with {
		if user == recipientUsername {
			seen = true
			break
		}
	}
	if !seen {
		return errors.New(strings.ToTitle("Revoked user is not in owner's namespace"))
	}

	invitation_uuid := ownMap.Invitation_UUID
	random_bytes := userlib.RandomBytes(16)
	userlib.DatastoreSet(invitation_uuid, random_bytes)
	return nil
}

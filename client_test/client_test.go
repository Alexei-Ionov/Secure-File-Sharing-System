package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const secondPassword = "wrongPassword"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================
func helper_Tamper_File(uuid_to_tamper userlib.UUID) {
	random_bytes := userlib.RandomBytes(100)
	userlib.DatastoreSet(uuid_to_tamper, random_bytes)
}

func get_most_recently_added_uuid(ds1 map[userlib.UUID][]byte, ds2 map[userlib.UUID][]byte) (ret userlib.UUID) {
	for uuid, _ := range ds2 {
		// _, okOwn := userdata.Files_Owned[File_PTR_local]
		_, found := ds1[uuid]
		if !found {
			return uuid
		}
	}
	return
}

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			alicecontent, err := aliceDesktop.LoadFile(aliceFile)
			userlib.DebugMsg("after bob append appending to file [alice pov] %s", alicecontent)

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	/*
		basic tests on init user including:
		1.) same username test
		2.) empty username test
	*/
	Describe("Tests InitUser Functionality", func() {
		Specify("Tests to see if same username passes", func() {
			userlib.DebugMsg("Initializing user Bob.")
			_, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempt to create another user with same username.")
			_, err = client.InitUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil(), "Could not find repeat usernames")
		})
		Specify("Checking to see valid username", func() {
			userlib.DebugMsg("Initializing user with empty username.")
			_, err := client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

	})

	/*
		basic tests for get user including:
		1.) user doesn't exist
		2.) invalid credentials
		3.) tests multiple users with same password.
		4.) compromised user struct

	*/
	Describe("Tests GetUser Functionality", func() {
		Specify("Test invalid username", func() {
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempt to login to an invalid username.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
		Specify("Basic Test: Invalid credentials (wrong password)", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", secondPassword)
			Expect(err).ToNot(BeNil())
		})
		Specify("Basic Test: testing multiple users with same password", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

		})
		Specify("Basic Test: Tampered user struct", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			var user_uuid userlib.UUID
			user_uuid, err = uuid.FromBytes(userlib.Hash([]byte("alice" + defaultPassword))[:16])
			helper_Tamper_File(user_uuid)
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

		})
	})
	/*

				basic tests for file operations including:
				1.) tampering with file af
				2.) tampering with file after store file is called
					(userA stores file. file gets tampered with. userA then tries to store/load/append to file)


		Note that calling StoreFile after malicious tampering has occurred is undefined behavior, and will not be tested.
		Note that calling StoreFile on a file whose access has been revoked is undefined behavior, and will not be tested.
	*/
	Describe("Tests store/load/append Functionality", func() {

		Specify("Test filename in user namespace", func() {
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob storing file %s with content: %s", bobFile, contentOne)
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice tries to load file without access")
			_, err := alice.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

		})
		// Specify("Test tampering of file -- loaded by user owner", func() {
		// 	userlib.DebugMsg("Initializing user Bob.")
		// 	bob, err = client.InitUser("bob", defaultPassword)
		// 	Expect(err).To(BeNil())

		// 	ds1 := userlib.DatastoreGetMap()

		// 	userlib.DebugMsg("bob storing file %s with content: %s", bobFile, contentOne)

		// 	err = bob.StoreFile(bobFile, []byte(contentOne))
		// 	Expect(err).To(BeNil())

		// 	err = bob.AppendToFile(bobFile, []byte("hi"))
		// 	Expect(err).To(BeNil())

		// 	err = bob.AppendToFile(bobFile, []byte("there"))
		// 	Expect(err).To(BeNil())

		// 	err = bob.AppendToFile(bobFile, []byte("friend"))
		// 	Expect(err).To(BeNil())

		// 	ds2 := userlib.DatastoreGetMap()

		// 	file_uuid := get_most_recently_added_uuid(ds1, ds2)
		// 	userlib.DebugMsg("file uuid %s ", file_uuid)

		// 	helper_Tamper_File(file_uuid)

		// 	_, err := bob.LoadFile(bobFile)
		// 	Expect(err).ToNot(BeNil())
		// })

	})

})

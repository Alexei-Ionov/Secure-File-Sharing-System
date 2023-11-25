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
	for uuid := range ds2 {
		_, found := ds1[uuid]
		if !found {
			return uuid
		}
	}

	return
}

func deepCopyMap(inputMap map[userlib.UUID][]byte) map[userlib.UUID][]byte {
	copyMap := make(map[userlib.UUID][]byte, len(inputMap))
	for key, value := range inputMap {
		// Create a new slice with the same length as the original
		copyValue := make([]byte, len(value))
		// Copy the elements from the original slice to the new one
		copy(copyValue, value)

		// Assign the copied slice to the new map
		copyMap[key] = copyValue
	}

	return copyMap
}

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	var frank *client.User
	var grace *client.User
	var horace *client.User
	var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	small_sized_file := "smallFile.txt"
	big_sized_file := "bigFile.txt"
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
		Specify("Basic Test: tampered DSMap", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			dsMap := userlib.DatastoreGetMap()
			for key := range dsMap {
				dsMap[key] = []byte("random stuff")
			}
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

		Specify("Test filename in user namespace, loadfile ", func() {
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

		Specify("Testing file storing after creation by both owner and non-owner", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice shares file w/ bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, "bobfile")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob appends to file")
			err = bob.AppendToFile("bobfile", []byte("herro"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice also appends to file")

			err = alice.AppendToFile(aliceFile, []byte("bye bye - from alice"))
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("overwriting this bihhhh"))
			Expect(err).To(BeNil())

			content, err := bob.LoadFile("bobfile")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("overwriting this bihhhh")))

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = bob.StoreFile("bobfile", []byte(contentOne+contentTwo))
			Expect(err).To(BeNil())

			content, err = bob.LoadFile("bobfile")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne + contentTwo)))

		})
		Specify("Test tampering of file from head -- loaded by user owner", func() {
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			ds1 := deepCopyMap(userlib.DatastoreGetMap())

			userlib.DebugMsg("bob storing file %s with content: %s", bobFile, contentOne)

			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			ds2 := userlib.DatastoreGetMap()

			file_uuid := get_most_recently_added_uuid(ds1, ds2)

			helper_Tamper_File(file_uuid)

			_, err := bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
		})
		Specify("Test tampering of file from tail of file -- loaded by user sharee'", func() {
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob storing file %s with content: %s", bobFile, contentOne)

			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = bob.AppendToFile(bobFile, []byte("hi"))
			Expect(err).To(BeNil())

			err = bob.AppendToFile(bobFile, []byte("there"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob creating invite for alice.")
			invite, err := bob.CreateInvitation(bobFile, "alice")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice accepting invite from bob under filename %s.", bobFile)
			err = alice.AcceptInvitation("bob", invite, "my_file")
			Expect(err).To(BeNil())

			ds1 := deepCopyMap(userlib.DatastoreGetMap())

			err = alice.AppendToFile("my_file", []byte("friend"))
			Expect(err).To(BeNil())

			ds2 := userlib.DatastoreGetMap()

			file_uuid := get_most_recently_added_uuid(ds1, ds2)
			helper_Tamper_File(file_uuid)

			_, err = alice.LoadFile("my_file")
			Expect(err).ToNot(BeNil())
		})
		Specify("Test filename in user namespace, appending", func() {
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
			err := alice.AppendToFile(bobFile, []byte("bob sucks lol"))
			Expect(err).ToNot(BeNil())

		})
		Specify("testing if filename can be an empty string", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice storing file with empty file name with content: %s", contentOne)
			err = alice.StoreFile("", []byte(contentOne))
			Expect(err).To(BeNil())
		})

		Specify("testing if contents can be empty", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file with empty file name without content (storing): %s", emptyString)
			err = alice.StoreFile("aliceFile", []byte(emptyString))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file with empty file name without content (appending): %s", emptyString)
			err = alice.AppendToFile("aliceFile", []byte(emptyString))
			Expect(err).To(BeNil())

			_, err := alice.LoadFile("aliceFile")
			Expect(err).To(BeNil())

		})

		Specify("Basic Test: tampered DSMap", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file with empty file name without content (storing): %s", emptyString)
			err = alice.StoreFile("aliceFile", []byte(emptyString))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file with empty file name without content (appending): %s", emptyString)
			err = alice.AppendToFile("aliceFile", []byte(emptyString))
			Expect(err).To(BeNil())

			dsMap := userlib.DatastoreGetMap()
			for key := range dsMap {
				dsMap[key] = []byte("random stuff")
			}

			_, err := alice.LoadFile("aliceFile")
			Expect(err).ToNot(BeNil())

		})

	})
	Describe("Testing append efficency and scalability", func() {
		measureBandwidth := func(probe func()) (bandwidth int) {
			before := userlib.DatastoreGetBandwidth()
			probe()
			after := userlib.DatastoreGetBandwidth()
			return after - before
		}
		///TEST TO SEE IF PREV FILE/APPEND SIZE AFFECTS EFFiciency
		Specify("Test Append does not scale with Size of File", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(small_sized_file, []byte(contentOne))
			Expect(err).To(BeNil())

			content_for_big_sized_file := string(make([]byte, 123445667))

			userlib.DebugMsg("Storing file data: %s", big_sized_file)
			err = alice.StoreFile(big_sized_file, []byte(content_for_big_sized_file))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting bandwidth of appending to smaller file")
			small_file_bw := measureBandwidth(func() {
				err = alice.AppendToFile(small_sized_file, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			userlib.DebugMsg("Getting bandwidth of appending to bigger file")
			big_file_bw := measureBandwidth(func() {
				err = alice.AppendToFile(big_sized_file, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			bandwidth_comparison := small_file_bw == big_file_bw

			Expect(bandwidth_comparison).To(BeTrue())

		})

		///TEST TO SEE HOW NUMBER OF APPPENDS AFFECTS EFFicieny

		Specify("test to see if number of appends scales efficiently", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s in aliceFile", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s in bobFile", contentOne)
			err = alice.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("getting bw after first append")
			first_bw := measureBandwidth(func() {
				err = alice.AppendToFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			userlib.DebugMsg("Append many many more times (10,000 as said in spec)")
			for i := 0; i < 10000; i++ {
				alice.AppendToFile(bobFile, []byte(contentOne))
			}

			userlib.DebugMsg("getting bandwhith of append to file with many appends already to it")
			last_bw := measureBandwidth(func() {
				err = alice.AppendToFile(bobFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			bandwidth_comparison := first_bw == last_bw

			Expect(bandwidth_comparison).To(BeTrue())
		})
		Specify("Test to see if append bandwidth is affected by number of users file is shared with ", func() {

			//init a bunch of users
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			before_people_bw := measureBandwidth(func() {
				err = alice.AppendToFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user frank.")
			frank, err = client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user ira.")
			ira, err = client.InitUser("ira", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user doris.")
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user eve.")
			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user grace.")
			grace, err = client.InitUser("grace", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user horace.")
			horace, err = client.InitUser("horace", defaultPassword)
			Expect(err).To(BeNil())

			///adding multiple people
			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			///adding multiple people
			userlib.DebugMsg("aliceLaptop creating invite for charles.")
			invite, err = aliceLaptop.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("charles accepting invite from Alice under filename %s.", charlesFile)
			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for eve.")
			invite, err = aliceLaptop.CreateInvitation(aliceFile, "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("eve accepting invite from Alice under filename %s.", "my_file")
			err = eve.AcceptInvitation("alice", invite, "my_file")
			Expect(err).To(BeNil())
			///adding multiple people
			userlib.DebugMsg("aliceLaptop creating invite for frank.")
			invite, err = aliceLaptop.CreateInvitation(aliceFile, "frank")
			Expect(err).To(BeNil())

			userlib.DebugMsg("frank accepting invite from Alice under filename %s.", "my_file")
			err = frank.AcceptInvitation("alice", invite, "my_file")
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for doris.")
			invite, err = aliceLaptop.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("doris accepting invite from Alice under filename %s.", "my_file")
			err = doris.AcceptInvitation("alice", invite, "my_file")
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for grace.")
			invite, err = aliceLaptop.CreateInvitation(aliceFile, "grace")
			Expect(err).To(BeNil())

			userlib.DebugMsg("grace accepting invite from Alice under filename %s.", "my_file")
			err = grace.AcceptInvitation("alice", invite, "my_file")
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for horace.")
			invite, err = aliceLaptop.CreateInvitation(aliceFile, "horace")
			Expect(err).To(BeNil())

			userlib.DebugMsg("horace accepting invite from Alice under filename %s.", "my_file")
			err = horace.AcceptInvitation("alice", invite, "my_file")
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for ira.")
			invite, err = aliceLaptop.CreateInvitation(aliceFile, "ira")
			Expect(err).To(BeNil())

			userlib.DebugMsg("ira accepting invite from Alice under filename %s.", "my_file")
			err = ira.AcceptInvitation("alice", invite, "my_file")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting bandwidth after multiple people have access")

			after_people_bw := measureBandwidth(func() {
				err = alice.AppendToFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})
			num_people := 9 //total nuber of users which the file is shared with
			bandwidth_comparison := (before_people_bw * num_people) <= after_people_bw

			//check to see if it scales with number of people
			userlib.DebugMsg("before people bw: %d", before_people_bw)
			userlib.DebugMsg("after people bw: %d", after_people_bw)
			Expect(bandwidth_comparison).To(BeFalse())

		})

		//testing appending bw in response to username length
		Specify("Test Append does not scale with length of username", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing long username user.")
			long_username_user, err := client.InitUser("longgggggggggggggggggggguserrrrrrrrrrrrrrrrnameeeeeeeeeeeeeeeeeeeeeee", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = long_username_user.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting bandwidth of appending to file with a relatively short username (i.e. alice)")
			small_username_bw := measureBandwidth(func() {

				for i := 0; i < 5000; i++ {
					err = alice.AppendToFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())
				}

			})

			userlib.DebugMsg("Getting bandwidth of appending to file with a longer username")
			big_username_bw := measureBandwidth(func() {
				for i := 0; i < 5000; i++ {
					err = long_username_user.AppendToFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())
				}

			})
			username_length_diff := len(long_username_user.Username) - len(alice.Username)
			userlib.DebugMsg("small username bw: %d", small_username_bw)
			userlib.DebugMsg("large username bw: %d", big_username_bw)
			bandwidth_comparison := (small_username_bw * username_length_diff) <= big_username_bw
			Expect(bandwidth_comparison).To(BeFalse())

		})

		Specify("Test Append does not scale with length of password", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			long_password := "thissssssssssssssssssssisssssssssssssssssaaaaaaaaaaalonggggggggasssssssspasssssssssworddddddddlollllllllllllll"
			userlib.DebugMsg("Initializing long password user.")
			long_password_user, err := client.InitUser("long_password_user", long_password)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = long_password_user.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting bandwidth of appending to file with a relatively short passowrd (i.e. password)")
			small_password_bw := measureBandwidth(func() {

				for i := 0; i < 5000; i++ {
					err = alice.AppendToFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())
				}

			})

			userlib.DebugMsg("Getting bandwidth of appending to file with a longer password")
			big_password_bw := measureBandwidth(func() {
				for i := 0; i < 5000; i++ {
					err = long_password_user.AppendToFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())
				}

			})
			password_len_diff := len(long_password) - len(defaultPassword)
			userlib.DebugMsg("small username bw: %d", small_password_bw)
			userlib.DebugMsg("large username bw: %d", big_password_bw)
			bandwidth_comparison := (small_password_bw * password_len_diff) <= big_password_bw
			Expect(bandwidth_comparison).To(BeFalse())

		})
		Specify("Test Append does not scale with length of filename", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			long_file_name := "thissssssssssssssssssssisssssssssssssssssaaaaaaaaaaalonggggggggassssssssfileeeeeenameeeeeeeeeeelollllllllllllll"
			userlib.DebugMsg("Initializing other user.")
			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = bob.StoreFile(long_file_name, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting bandwidth of appending to file with a relatively short file name (i.e. alicefile)")
			small_filename_bw := measureBandwidth(func() {

				for i := 0; i < 5000; i++ {
					err = alice.AppendToFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())
				}

			})

			userlib.DebugMsg("Getting bandwidth of appending to file with a longer filename")
			big_filename_bw := measureBandwidth(func() {
				for i := 0; i < 5000; i++ {
					err = bob.AppendToFile(long_file_name, []byte(contentOne))
					Expect(err).To(BeNil())
				}

			})
			file_name_diff := len(long_file_name) - len(aliceFile)
			userlib.DebugMsg("small filename bw: %d", small_filename_bw)
			userlib.DebugMsg("large filename bw: %d", big_filename_bw)
			bandwidth_comparison := (small_filename_bw * file_name_diff) <= big_filename_bw
			Expect(bandwidth_comparison).To(BeFalse())

		})
		Specify("Test Append does not scale with number of files", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting bandwidth of appending to file with only 1 alr exisitng file")
			less_files_bw := measureBandwidth(func() {
				for i := 0; i < 5000; i++ {
					err = alice.AppendToFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())
				}

			})

			err = alice.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.StoreFile(charlesFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.StoreFile("hi", []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.StoreFile("file", []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.StoreFile("someFile", []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.StoreFile("my_file", []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.StoreFile("our_file", []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.StoreFile("ninth_file", []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.StoreFile("tenthfile", []byte(contentOne))
			Expect(err).To(BeNil())

			more_files_bw := measureBandwidth(func() {
				for i := 0; i < 5000; i++ {
					err = alice.AppendToFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())
				}

			})

			scale := 10
			userlib.DebugMsg("small filename bw: %d", less_files_bw)
			userlib.DebugMsg("large filename bw: %d", more_files_bw)
			bandwidth_comparison := (less_files_bw * scale) <= more_files_bw
			Expect(bandwidth_comparison).To(BeFalse())
		})

	})

	/*
		TESTING create invitation/ accept invitetation/ revoke access
	*/
	Describe("Testing create/accept/revoke", func() {

		//CREATE INVITATION
		Specify("Testing to see if filename is in namespace of owner when sharing", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice attempts to create invitation to bob for a file she doesn't own.")
			_, err := alice.CreateInvitation(bobFile, "bob")
			Expect(err).ToNot(BeNil())
		})
		Specify("Test for recipient user not existing", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice attempts to create invitation to bob for a file she doesn't own.")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		//ACCEPT INVITATION/REVOKE
		Specify("Testing to see if filename is alr in namespace of user when sharing", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(charlesFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice attempts to create invitation to bob for a file")
			invite1, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite1, "bobfile")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice attempts to create invitation to bob for a file she doesn't own.")
			invite2, err := alice.CreateInvitation(charlesFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite2, "bobfile")
			Expect(err).ToNot(BeNil())
		})
		Specify("Testing tampering with invitePtr", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice attempts to create invitation to bob for a file she doesn't own.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			helper_Tamper_File(invite)

			err = bob.AcceptInvitation("alice", invite, "bobfile")
			Expect(err).ToNot(BeNil())

		})
		Specify("Testing owner trying to create an invite and other user trying to accept from non-owner", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice attempts to create invitation to bob for a file she doesn't own.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("mallory", invite, "bobfile")
			Expect(err).ToNot(BeNil())

		})
		Specify("Testing basic revocation & trying to get re-access after being revocated", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creates invite to bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, "bobfile")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob can load file (still has access).")
			_, err = bob.LoadFile("bobfile")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice revokes bob's access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob tries to load file after being revoked.")
			_, err = bob.LoadFile("bobfile")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("bob tries to append to file after being revoked.")
			err = bob.AppendToFile("bobfile", []byte("hi"))
			Expect(err).ToNot(BeNil())

		})
		Specify("Testing file name not in namespace for revoke access", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice attempts to create invitation to bob for a file she doesn't own.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, "bobfile")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice revokes bob's access")
			err = alice.RevokeAccess(bobFile, "bob")
			Expect(err).ToNot(BeNil())

		})
		Specify("Testing file not shared with user, failed revoke", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice revokes bob's access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

		})
		Specify("Testing that revoked user's and all the users they shared with are revoked", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user eve.")
			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user frank.")
			frank, err = client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice shares file w/ bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, "bobfile")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob shares file w/ charles")
			invite, err = bob.CreateInvitation("bobfile", "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, "charlesfile")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob shares file w/ frank")
			invite, err = bob.CreateInvitation("bobfile", "frank")
			Expect(err).To(BeNil())

			err = frank.AcceptInvitation("bob", invite, "frankfile")
			Expect(err).To(BeNil())

			userlib.DebugMsg("frank shares file w/ eve")
			invite, err = frank.CreateInvitation("frankfile", "eve")
			Expect(err).To(BeNil())

			err = eve.AcceptInvitation("frank", invite, "evefile")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice revokes bob's access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob tries to load file after being revoked.")
			_, err = bob.LoadFile("bobfile")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("bob tries to append to file after being revoked.")
			err = bob.AppendToFile("bobfile", []byte("hi"))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("charles tries to load file after being revoked.")
			_, err = charles.LoadFile("charlesfile")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("charles tries to append to file after being revoked.")
			err = charles.AppendToFile("charlesfile", []byte("hi"))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("frank tries to load file after being revoked.")
			_, err = frank.LoadFile("frankfile")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("frank tries to append to file after being revoked.")
			err = frank.AppendToFile("frankfile", []byte("hi"))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("eve tries to load file after being revoked.")
			_, err = eve.LoadFile("evefile")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("eve tries to append to file after being revoked.")
			err = eve.AppendToFile("evefile", []byte("hi"))
			Expect(err).ToNot(BeNil())

		})
		Specify("Testing that users with access still have access after others get revoked", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creates invite to bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, "bobfile")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creates invite to charles")
			invite2, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invite2, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob can load file (still has access).")
			_, err = bob.LoadFile("bobfile")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice revokes bob's access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob tries to load file after being revoked.")
			_, err = bob.LoadFile("bobfile")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("bob tries to append to file after being revoked.")
			err = bob.AppendToFile("bobfile", []byte("hi"))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("charles tries to load file after bob got revoked")
			content, err := charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne)))

			err = alice.AppendToFile(aliceFile, []byte("hey there"))
			Expect(err).To(BeNil())

			err = alice.AppendToFile(aliceFile, []byte("charles"))
			Expect(err).To(BeNil())

			content, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne + "hey there" + "charles")))

		})

		Specify("Basic Test for accept : tampered DSMap", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file with empty file name without content (storing): %s", emptyString)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file with empty file name without content (appending): %s", emptyString)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creates invite to bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			dsMap := userlib.DatastoreGetMap()
			for key := range dsMap {
				dsMap[key] = []byte("random stuff")
			}

			err = bob.AcceptInvitation("alice", invite, "bobfile")
			Expect(err).ToNot(BeNil())

		})
		Specify("Basic Test for revoke: tampered DSMap", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file with empty file name without content (storing): %s", emptyString)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file with empty file name without content (appending): %s", emptyString)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creates invite to bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, "bobfile")
			Expect(err).ToNot(BeNil())

			dsMap := userlib.DatastoreGetMap()
			for key := range dsMap {
				dsMap[key] = []byte("random stuff")
			}

			userlib.DebugMsg("alice revokes bob's access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

		})
	})

	/*

		EDGE CASE TESTING

	*/

	Describe("Testing edge cases", func() {
		Specify("testing what happens when invite structs get swapped", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			//init user, store contents, and createInvitation
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice storing file %s with content: %s", bobFile, contentTwo)
			alice.StoreFile(bobFile, []byte(contentTwo))

			userlib.DebugMsg("Alice creating invite for Bob for file %s", aliceFile)
			invite1, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Charles for file %s", bobFile)
			invite2, err := alice.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("swapping invite structs here")
			dsMap := userlib.DatastoreGetMap()
			temp := dsMap[invite1]
			dsMap[invite1] = dsMap[invite2]
			dsMap[invite2] = temp

			//here both bob and charles try to decrypt the rsa struct with their private RSA key yet it was initally encrypted with the public RSA key of the other.
			//hence, they should NOT be able to accept the invite
			err = bob.AcceptInvitation("alice", invite1, "my_file")
			Expect(err).ToNot(BeNil())

			err = charles.AcceptInvitation("alice", invite2, charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("now bob will attempt to load/append to a file that he doens't actually have access to")
			_, err = bob.LoadFile("my_file")
			Expect(err).ToNot(BeNil())

		})
		Specify("testing revoke access before call to accept invitation", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			//init user, store contents, and createInvitation
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s", aliceFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob attempts to accept invite even after alr being revoked. should err")
			err = bob.AcceptInvitation("alice", invite, "my_file")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("now bob will attempt to load/append to a file that he doens't actually have access to")
			_, err = bob.LoadFile("my_file")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("now bob will attempt to load/append to a file that he doens't actually have access to")
			err = bob.AppendToFile("my_file", []byte("lemmme in"))
			Expect(err).ToNot(BeNil())

		})

	})

})

package drum

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

// Format of the file
//
// Byte order: little endian
//
// File header:
//
//	Format: 13 bytes, 0 padded
//	Total data length: 1 byte
//	Writer version: 32 bytes, 0 padded
//	Tempo (bpm): 4 bytes, float
//	Tracks
//
// Track format:
//
//	Track id: 32 bit unsigned int
//	Track name lenght: 1 byte
//	Track name: n bytes, as indicated by previous field
//	Data: 16 bytes, 1 byte per step

const (
	formatFieldBytes     = 13
	dataLengthFieldBytes = 1
	headerBytes          = formatFieldBytes + dataLengthFieldBytes
	versionFieldBytes    = 32
	tempoFieldBytes      = 4
	tracksOffset         = headerBytes + versionFieldBytes + tempoFieldBytes
)

var (
	spliceByteOrder      = binary.LittleEndian
	spliceMarker         = [formatFieldBytes]byte{'S', 'P', 'L', 'I', 'C', 'E'}
	ErrInvalidFileFormat = errors.New("Bad format")
	ErrInsufficientData  = errors.New("file is shorter than expected")
)

// DecodeFile decodes the drum machine file found at the provided path
// and returns a pointer to a parsed pattern which is the entry point to the
// rest of the data.
func DecodeFile(path string) (*Pattern, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s, err := f.Stat()
	if err != nil {
		return nil, err
	}

	p, datalen, err := readHeader(f, s.Size())
	if err != nil {
		return nil, err
	}

	// the DataLength field in the file includes the lenghts of the
	// version and the tempo fields. Reading the header has already
	// consumed those two fields
	datalen -= versionFieldBytes + tempoFieldBytes

	r := io.LimitReader(f, datalen)

	if p.Tracks, err = readTracks(r); err != nil {
		return nil, err
	}

	return p, nil
}

// getVersionAsString returns a string representation of the version
// header.
func getVersionAsString(writer []byte) string {
	n := bytes.Index(writer, []byte{0})
	if n == -1 {
		n = len(writer)
	}
	return string(writer[:n])
}

// readHeader decodes the drum machine file's header.
//
// "r" is positioned at the start of the file.
//
// "s" is the total bytes available from the reader. It is used to
// validate that the data length indicated in the file does not go past
// the information available from the reader.
//
// It returns the Pattern filled with Version and Tempo, and the data
// length indicated in the header.
func readHeader(r io.Reader, s int64) (*Pattern, int64, error) {
	header := struct {
		Format     [formatFieldBytes]byte
		DataLength uint8
		Writer     [versionFieldBytes]byte
		Tempo      float32
	}{}

	if err := binary.Read(r, spliceByteOrder, &header); err != nil {
		return nil, 0, err
	}

	if spliceMarker != header.Format {
		return nil, 0, ErrInvalidFileFormat
	}

	if expected := headerBytes + int64(header.DataLength); s < expected {
		return nil, 0, ErrInsufficientData
	}

	p := &Pattern{
		Version: getVersionAsString(header.Writer[:]),
		Tempo:   header.Tempo,
	}

	return p, int64(header.DataLength), nil
}

type trackReader struct {
	r     io.Reader
	order binary.ByteOrder
	err   error
}

func (t *trackReader) Read(data interface{}) {
	if t.err != nil {
		return
	}

	t.err = binary.Read(t.r, t.order, data)
}

// readtracks will decode the track information contained in the drum
// machine file.
//
// "r" should point at the start of the track data
func readTracks(r io.Reader) ([]Track, error) {
	tracks := []Track{}

	t := &trackReader{r: r, order: spliceByteOrder}

	for t.err == nil {
		header := struct {
			ID      uint32
			NameLen uint8
		}{}
		t.Read(&header)

		name := make([]byte, header.NameLen)
		t.Read(&name)

		track := Track{
			ID:   int(header.ID),
			Name: string(name),
		}
		t.Read(&track.Data)

		if t.err == nil {
			tracks = append(tracks, track)
		}
	}

	return tracks, nil
}

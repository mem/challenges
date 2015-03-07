package drum

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
)

var SpliceMarker = [13]byte{'S', 'P', 'L', 'I', 'C', 'E'}

const (
	FormatFieldBytes     = 13
	DataLengthFieldBytes = 1
	VersionFieldBytes    = 32
	TempoFieldBytes      = 4
	HeaderBytes          = FormatFieldBytes + DataLengthFieldBytes
	TracksOffset         = HeaderBytes + VersionFieldBytes + TempoFieldBytes
)

// DecodeFile decodes the drum machine file found at the provided path
// and returns a pointer to a parsed pattern which is the entry point to the
// rest of the data.
func DecodeFile(path string) (*Pattern, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewReader(b)
	byteorder := binary.LittleEndian

	header := struct {
		Format     [FormatFieldBytes]byte
		DataLength uint8 // there seems to be a single byte with the length
		Writer     [VersionFieldBytes]byte
		Tempo      float32
	}{}

	binary.Read(buf, byteorder, &header)

	if SpliceMarker != header.Format {
		return nil, errors.New("Bad format")
	}

	if l := len(b); l < int(header.DataLength) {
		err := errors.New(fmt.Sprintf("Not enough data in file: %d vs %d", l, header.DataLength))
		return nil, err
	}

	n := bytes.Index(header.Writer[:], []byte{0})
	p := &Pattern{
		Version: string(header.Writer[:n]),
		Tempo:   header.Tempo,
	}

	// Rebuild the buffer to limit to the amount of data that the file says is there
	buf = bytes.NewReader(b[TracksOffset : HeaderBytes+header.DataLength])

	for {
		trackHeader := struct {
			Id      uint8
			_       [3]byte
			NameLen uint8
		}{}

		if err := binary.Read(buf, byteorder, &trackHeader); err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, err
		}

		name := make([]byte, trackHeader.NameLen)
		if err := binary.Read(buf, byteorder, &name); err != nil {
			return nil, err
		}

		track := Track{
			Id:   int(trackHeader.Id),
			Name: string(name),
		}

		if err := binary.Read(buf, byteorder, &track.Data); err != nil {
			return nil, err
		}

		p.Tracks = append(p.Tracks, track)
	}

	return p, nil
}

// Pattern is the high level representation of the
// drum pattern contained in a .splice file.
type Pattern struct {
	Version string
	Tempo   float32
	Tracks  []Track
}

func (p *Pattern) String() string {
	s := fmt.Sprintf(
		"Saved with HW Version: %s\nTempo: %g\n",
		p.Version,
		p.Tempo)
	for _, track := range p.Tracks {
		s += track.String() + "\n"
	}
	return s
}

type Track struct {
	Id   int
	Name string
	Data Steps
}

func (t Track) String() string {
	return fmt.Sprintf("(%d) %s\t%s", t.Id, t.Name, t.Data)
}

type Steps [16]byte

func (s Steps) String() string {
	str := ""
	for i, b := range s {
		if i%4 == 0 {
			str += "|"
		}
		switch b {
		case 1:
			str += "x"
		case 0:
			str += "-"
		}
	}
	str += "|"
	return str
}

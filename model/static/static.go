package static

import rice "github.com/GeertJohan/go.rice"

func GetFileFromBox(path string) ([]byte, error) {
	box := rice.MustFindBox("../../static")
	httpBox := box.HTTPBox()

	buf, err := httpBox.Bytes(path)
	return buf, err
}

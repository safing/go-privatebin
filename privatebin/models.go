package privatebin

// PasteRequest .
type PasteRequest struct {
	V     int              `json:"v"`
	AData []interface{}    `json:"adata"`
	Meta  PasteRequestMeta `json:"meta"`
	CT    string           `json:"ct"`
}

// PasteRequestMeta .
type PasteRequestMeta struct {
	Expire string `json:"expire"`
}

// PasteResponse .
type PasteResponse struct {
	Status      int    `json:"status"`
	ID          string `json:"id"`
	URL         string `json:"url"`
	DeleteToken string `json:"deletetoken"`
}

// PasteContent .
type PasteContent struct {
	Paste          string `json:"paste"`
	Attachment     string `json:"attachment,omitempty"`
	AttachmentName string `json:"attachment_name,omitempty"`
}

// PasteSpec .
type PasteSpec struct {
	IV          string
	Salt        string
	Iterations  int
	KeySize     int
	TagSize     int
	Algorithm   string
	Mode        string
	Compression string
}

// SpecArray .
func (spec *PasteSpec) SpecArray() []interface{} {
	return []interface{}{
		spec.IV,
		spec.Salt,
		spec.Iterations,
		spec.KeySize,
		spec.TagSize,
		spec.Algorithm,
		spec.Mode,
		spec.Compression,
	}
}

// PasteData .
type PasteData struct {
	*PasteSpec
	Data []byte
}

// adata .
func (paste *PasteData) GetAData() []interface{} {
	return []interface{}{
		paste.SpecArray(),
		"plaintext",
		0,
		0,
	}
}

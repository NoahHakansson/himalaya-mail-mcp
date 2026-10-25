package mailmcp

import (
	"context"
	"os"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/himalaya"
)

// RefIn is the input of tools that take one message reference.
type RefIn struct {
	Account     Account     `json:"account"`
	Mailbox     Mailbox     `json:"mailbox"`
	UIDValidity UIDValidity `json:"uidvalidity"`
	UID         UID         `json:"uid"`
}

// AttachmentInfo is one non-inline attachment.
type AttachmentInfo struct {
	PartID   int    `json:"part_id"`
	Filename string `json:"filename"`
	MIME     string `json:"mime"`
	Size     int64  `json:"size"`
}

// ListAttachmentsOut is the output of list_attachments.
type ListAttachmentsOut struct {
	Account     string           `json:"account"`
	Mailbox     string           `json:"mailbox"`
	UIDValidity uint32           `json:"uidvalidity"`
	UID         uint32           `json:"uid"`
	Attachments []AttachmentInfo `json:"attachments"`
}

func (s *Server) listAttachments(ctx context.Context, in RefIn) (ListAttachmentsOut, error) {
	a, mb, uv, uid, err := s.refIn(in.Account, in.Mailbox, in.UIDValidity, in.UID)
	if err != nil {
		return ListAttachmentsOut{}, err
	}
	if err := s.readRef(ctx, a, mb, uv, uid); err != nil {
		return ListAttachmentsOut{}, err
	}
	raw, err := s.run.Run(ctx, a.hx.AttachmentList(mb, uid))
	if err != nil {
		return ListAttachmentsOut{}, withMailbox(err, mb)
	}
	atts, err := himalaya.ParseAttachments(raw)
	if err != nil {
		return ListAttachmentsOut{}, mailError()
	}
	out := ListAttachmentsOut{Account: a.cfg.Name, Mailbox: mb, UIDValidity: uv, UID: uid, Attachments: []AttachmentInfo{}}
	for _, at := range atts {
		if at.Inline {
			continue
		}
		out.Attachments = append(out.Attachments, AttachmentInfo{
			PartID: at.PartID, Filename: sanitizeLine(at.Filename), MIME: sanitizeLine(at.MIME), Size: at.Size,
		})
	}
	return out, nil
}

// DownloadIn is the input of download_attachment.
type DownloadIn struct {
	Account     Account     `json:"account"`
	Mailbox     Mailbox     `json:"mailbox"`
	UIDValidity UIDValidity `json:"uidvalidity"`
	UID         UID         `json:"uid"`
	PartID      PartID      `json:"part_id"`
}

// DownloadOut is the output of download_attachment. File is a bare name in the account's files directory.
type DownloadOut struct {
	File   string `json:"file"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	MIME   string `json:"mime"`
}

func (s *Server) downloadAttachment(ctx context.Context, in DownloadIn) (DownloadOut, error) {
	a, mb, uv, uid, err := s.refIn(in.Account, in.Mailbox, in.UIDValidity, in.UID)
	if err != nil {
		return DownloadOut{}, err
	}
	part, err := bounded("part_id", in.PartID, 1, maxPartID, 0)
	if err != nil || part == 0 {
		return DownloadOut{}, invalid("part_id", "must be 1..100000")
	}
	if err := s.readRef(ctx, a, mb, uv, uid); err != nil {
		return DownloadOut{}, err
	}
	tmp, err := os.MkdirTemp(s.tmpDir(), "dl-")
	if err != nil {
		return DownloadOut{}, err
	}
	defer os.RemoveAll(tmp)
	raw, err := s.run.Run(ctx, a.hx.AttachmentDownload(mb, tmp, uid, part))
	if err != nil {
		return DownloadOut{}, withMailbox(err, mb)
	}
	atts, err := himalaya.ParseAttachments(raw)
	if err != nil || len(atts) != 1 || atts[0].PartID != part {
		return DownloadOut{}, mailError()
	}
	name := storedName(s.now(), atts[0].Filename)
	size, sum, err := saveDownload(tmp, a.files, name, s.cfg.Limits.MaxAttachmentBytes)
	if err != nil {
		return DownloadOut{}, err
	}
	return DownloadOut{File: name, Size: size, SHA256: sum, MIME: sanitizeLine(atts[0].MIME)}, nil
}

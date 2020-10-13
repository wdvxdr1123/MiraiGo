package client

import (
	"errors"
	"fmt"
	"github.com/Mrs4s/MiraiGo/binary/pb/cmd0x346"
	"github.com/Mrs4s/MiraiGo/protocol/packets"
	"google.golang.org/protobuf/proto"
)

func (c *QQClient) buildOfflineFileDownloadRequestPacket(uuid []byte) (uint16, []byte) {
	seq := c.nextSeq()
	req := &cmd0x346.ReqBody{
		Cmd:        1200,
		Seq:        int32(seq),
		BusinessId: 3,
		ClientType: 104,
		ApplyDownloadReq: &cmd0x346.ApplyDownloadReq{
			Uin:       c.Uin,
			Uuid:      uuid,
			OwnerType: 2,
		},
		ExtensionReq: &cmd0x346.ExtensionReq{
			DownloadUrlType: 1,
		},
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "OfflineFilleHandleSvr.pb_ftn_CMD_REQ_APPLY_DOWNLOAD-1200", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

func decodeOfflineFileDownloadResponse(c *QQClient, _ uint16, payload []byte) (interface{}, error) {
	rsp := cmd0x346.RspBody{}
	if err := proto.Unmarshal(payload, &rsp); err != nil {
		c.Error("unmarshal cmd0x346 rsp body error: %v", err)
		return nil, err
	}
	if rsp.ApplyDownloadRsp == nil {
		c.Error("decode apply download 1200 error: apply rsp is nil.")
		return nil, errors.New("apply rsp is nil")
	}
	if rsp.ApplyDownloadRsp.RetCode != 0 {
		c.Error("decode apply download 1200 error: %v", rsp.ApplyDownloadRsp.RetCode)
		return nil, errors.New(fmt.Sprint(rsp.ApplyDownloadRsp.RetCode))
	}
	return "http://" + rsp.ApplyDownloadRsp.DownloadInfo.DownloadDomain + rsp.ApplyDownloadRsp.DownloadInfo.DownloadUrl, nil
}

#define DH_IS_RESPONSE(flags)        ((flags) & 0x8000)
#define DH_OPCODE(flags)             ((flags) & 0x7800)
#define DH_IS_AUTHORITATIVE(flags)   ((flags) & 0x0400)
#define DH_IS_TRUNC(flags)           ((flags) & 0x0200)
#define DH_REC_DESIRED(flags)        ((flags) & 0x0100)
#define DH_REC_AVAILABLE(flags)      ((flags) & 0x0080)
#define DH_RESERVED(flags)           ((flags) & 0x0070)
#define DH_RCODE(flags)              ((flags) & 0x000F)


#define DH_IS_POINTER(name)          (((name) & 0xC000) == 0xC000 ? 1 : 0)
#define DH_NAME_OFFSET(ptr)          (((ptr) & 0x3FFF))

#define IS_PRINTABLE(c) (((c) >= 32) && ((c) <= 126))

#define DH_OPCODE_QUERY              0
#define DH_OPCODE_IQUERY             1
#define DH_OPCODE_STATUS             2
#define DH_OPCODE_RESERVED           3
#define DH_OPCODE_NOTIFY             4
#define DH_OPCODE_UPDATE             5

/* RFC 1035 for explanations */
#define DH_RCODE_NO_ERR              0
#define DH_RCODE_FMT_ERR             1
#define DH_RCODE_SERV_ERR            2
#define DH_RCODE_NAME_ERR            3
#define DH_RCODE_NOT_IMPL            4
#define DH_RCODE_REFUSED             5
#define DH_RCODE_YX_DOMAIN           6
#define DH_RCODE_YX_RR_SET           7
#define DH_RCODE_NX_RR_SET           8
#define DH_RCODE_NOT_AUTH            9
#define DH_RCODE_NOTZONE             10

#define DH_RECORD_A                  1
#define DH_RECORD_CNAME              5

#define DNS_CLASS_IN                 1




//DNS Header
struct sniff_dns {
	uint16_t dh_id;
	uint16_t dh_flags;
	uint16_t dh_question_count;
	uint16_t dh_answer_count;
	uint16_t dh_name_server_count;
	uint16_t dh_additional_record_count;
};

--
-- SRS Protocols for data acquisition and slow-control, for use with Wireshark
-- Author: S. Martoiu
-- Copyright notice: Use at your own risk and all that... If you have a clever idea,
-- feel free to modify this code, with the condition to share it back to the comunity
--
-- Usage:
--    wireshark -X lua_script:<path>\srsproto.lua
--
-- Alternatively edit the init.lua file from the wireshark directory and add
-- the following lines at the end of the file:
--
-- SRSPROTO_SCRIPT_PATH="C:\\Path_to the_file\\"
-- dofile(SRSPROTO_SCRIPT_PATH.."srsproto.lua")
--
--
----------------------------------------------------------------
--                  SRS SC SECTION                            --
----------------------------------------------------------------
local udp_dissector_table = DissectorTable.get("udp.port")
old_dissector_6007 = udp_dissector_table:get_dissector(6007)


p_srssc = Proto ("srssc","SRS slow-control protocol")
local fsrssc = p_srssc.fields
local fsrssc_type = {[0] = "Reply", [1] = "Request"}
fsrssc.type = 		ProtoField.uint32("srssc.type", 	"Frame type", nil, fsrssc_type, 0x80000000)
fsrssc.reqid = 		ProtoField.uint32("srssc.reqid", 	"Request ID", base.HEX, nil, 0x7FFFFFFF)
fsrssc.subaddr = 	ProtoField.bytes ("srssc.subaddr", 	"Subaddr Field")
fsrssc.cmd = 		ProtoField.bytes ("srssc.cmd", 		"Command Field")
fsrssc.cmdinfo = 	ProtoField.bytes ("srssc.cmdinfo", 	"Command Info ")
fsrssc.error = 		ProtoField.uint32 ("srssc.error", 	"Error", base.HEX, nil, 0xFFFFFFFF)
--fsrssc.pdata = 		ProtoField.bytes ("srssc.pdata", 	"Payload data ")

function p_srssc.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit
--  if pkt.dst_port ~= 6007 then
--	old_dissector_6007:call(buf, pkt, root)
--	return
--  end
  
  if buf:len() == 0 then return end

  pkt.cols.protocol = p_srssc.name
  --pkt.cols.info = "SRS SC: "
  pkt.cols.info = ""
  
  if buf:len() == 8 then
	pkt.cols.info:append    ("[SC ERROR]")
	local subtree = root:add(p_srssc, buf(0))
		subtree:add(fsrssc.type, buf(0,4))
		subtree:add(fsrssc.reqid, buf(0,4))
		subtree:add(fsrssc.error, buf(4,4))
  elseif buf:len() > 16 then
	local frame_type = ""
	if buf(0,1):uint() >= 0x80 then
		frame_type = "request"
		pkt.cols.info:append("[SC Request] Dst. port: " .. pkt.dst_port)
	else
		frame_type = "reply"
		pkt.cols.info:append("[SC Reply]   Src. port: " .. pkt.src_port)
	end
	
	-- command decoding
	local cmd = buf(8,2):uint()
	local cmdtext = "undefined"
	if cmd == 0xaaaa then cmdtext = "write pairs" 
	elseif cmd == 0xaabb then cmdtext = "write burst" 
	elseif cmd == 0xbbbb then cmdtext = "read burst" 
	elseif cmd == 0xbbaa then cmdtext = "read list"
	end	
	-------
	local subtree = root:add(p_srssc, buf(0))
	subtree:append_text(": " .. cmdtext .. " " .. frame_type)
	subtree:add(fsrssc.type, buf(0,4))
	subtree:add(fsrssc.reqid, buf(0,4))
	subtree:add(fsrssc.subaddr, buf(4,4))
	subtree:add(fsrssc.cmd, buf(8,4)) :append_text(" (".. cmdtext ..")")
	subtree:add(fsrssc.cmdinfo, buf(12,4))
	
	local datatree = subtree:add(buf(16), "Payload Data:")
	
	for i = 16,buf:len()-4,4 do
		datatree:add(buf(i,4),""): append_text(tostring(buf(i,4):bytes()) .. " (" .. buf(i,4):uint() .. ")")
	end
  else
	pkt.cols.info:append("[invalid]")
	return
  end

  
end

function p_srssc.init()
end

  -- you can call dissector from function p_myproto.dissector above
  -- so that the previous dissector gets called
udp_dissector_table:add(6007, p_srssc)

----------------------------------------------------------------
--                 SRS DATA SECTION                           --
----------------------------------------------------------------

-- SRS Frame Data
p_srsfdata = Proto ("srsdata.framedata", "Frame Data")
local ffdata = p_srsfdata.fields
ffdata.raw = ProtoField.bytes("srsdata.framedata.raw", "Raw Data")

-- SRS APZ header
p_srsapzheader = Proto ("srsdata.apzheader", "APZ (Zero-suppression APV) Header")
local fapz = p_srsapzheader.fields
fapz.apvid = ProtoField.uint8("srsdata.apzheader.apvid", "APV_ID")
fapz.nchan = ProtoField.uint8("srsdata.apzheader.nchan", "N_CHANNELS")
fapz.nsamp = ProtoField.uint8("srsdata.apzheader.nsamp", "N_SAMPLES")
fapz.zserr = ProtoField.uint8("srsdata.apzheader.zserr", "ZS_ERROR")
fapz.flags = ProtoField.bytes("srsdata.apzheader.flags", "ZS_FLAGS")
	local zstype_array = {[0] = "Classic", [1] = "Peak-mode"}
	fapz.zstype = ProtoField.uint16 ("srsdata.apzheader.zstype", "Zero-suppression mode", nil, zstype_array, 0x01)
fapz.reserved = ProtoField.bytes("srsdata.apzheader.reserved", "RESERVED")

-- SRS APZ channel data
p_srsapzchdata = Proto("srsdata.apzchdata", "APZ Channel Data")
local fapzd = p_srsapzchdata.fields
fapzd.chan_info = ProtoField.uint8("srsdata.apzchdata.chan_info", "CHAN_INFO (RESERVED)")
fapzd.chan_id = ProtoField.uint8("srsdata.apzchdata.chan_id", "CHAN_ID")
fapzd.chan_peak = ProtoField.int16("srsdata.apzchdata.chan_id", "CHAN_PEAK")
fapzd.chan_time = ProtoField.uint16("srsdata.apzchdata.chan_id", "CHAN_TIME")
fapzd.chan_data = ProtoField.bytes("srsdata.apzchdata.chan_data", "CHAN_DATA")

-- SRS traffic proto
p_srstrailer = Proto ("srsdata.traffic", "SRS DATA traffic message")
ft_data = ProtoField.bytes("srsdata.traffic.data", "Data")
p_srstrailer.fields = {ft_data}
-- SRS frame header proto
p_srsframe = Proto ("srsdata.frame", "Frame Header")
ff_type = ProtoField.string("srsdata.frame.type", "Frame type")
ff_chan = ProtoField.uint8("srsdata.frame.chan", "Channel number")
ff_info = ProtoField.bytes("srsdata.frame.hinfo", "Frame Info")
p_srsframe.fields = {ff_type, ff_chan, ff_info}

-- create myproto protocol and its fields
p_myproto = Proto ("srsdata","SRS acquisition data")
local f_frameid = ProtoField.uint32("srsdata.frameid", "Frame ID", base.HEX)
local f_frameid8 = ProtoField.uint8("srsdata.frameid8", "Frame ID", base.DEC)
local f_timestamp = ProtoField.uint24("srsdata.timestamp", "Frame Timestamp", base.HEX)
--local f_header0 = ProtoField.bytes("srsdata.header0", "Frame Header")
--local f_data = ProtoField.bytes("srsdata.data", "Data")

--local f_debug = ProtoField.uint8("myproto.debug", "Debug")
--p_myproto.fields = {f_frameid, f_header0, f_data}
p_myproto.fields = {f_frameid, f_timestamp}

-- preferences

local pp = p_myproto.prefs
pp.enable_frame_timestamp = Pref.bool("Frame timestamp enabled", false, "Enable the frame_timestamp field")
pp.raw_decode = Pref.bool("Raw data decode", false, "Decode the raw data (slow)")
pp.raw_decode_limit = Pref.uint("Raw decode limit", 100, "Maximum number of samples to be decoded per frame")
-- APV decode preferences
pp.apv_static = Pref.statictext("Decode parameters for APV chip acquisition using ADC raw data mode (do enable also the raw data decode):")
pp.apv_decode = Pref.bool("Detect APV digital symbols", false, "Annotates the APV digital levels to the raw data samples.")
pp.apv_lowthr = Pref.uint("Low threshold for the APV digital symbol", 1000)
pp.apv_lowlabel = Pref.string("Symbol label for low threshold", "D1")
pp.apv_highthr = Pref.uint("High threshold for the APV digital symbol", 3000)
pp.apv_highlabel = Pref.string("Symbol label for high threshold", "D0")

pp.apz_static = Pref.statictext("Decode parameters for APV chip acquisition using the zero-suppression processor:")
pp.apz_decode = Pref.bool("APZ data decode", false, "Decode the APZ channel data")

-- myproto dissector function
function p_myproto.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end

  pkt.cols.protocol = p_myproto.name
  pkt.cols.info = "SRS DAQ: "

  if buf:len() == 4 then
	local traffic_message = "unknown"
	if buf(0,4):uint() == 0xfafafafa then
		traffic_message = "event trailer"
	end
	pkt.cols.info:append("[" .. traffic_message .. "]")
	subtree = root:add(p_srstrailer, buf(0))
		subtree:add(ft_data, buf(0)):append_text(" [" .. traffic_message .. "]")
	return 
  end
  
  pkt.cols.info:append("[data]")
  
  if buf(4,3):uint() == 0xcacaca then 
	pkt.cols.info:append(" [INVALID]")
	return
  end
  
  local frame_type = buf(4,3):string();
  local frame_channel = buf(7,1):uint();
  local frame_info = buf(8, 4);
  
  pkt.cols.info:append(" [Type: " .. frame_type .. ", Info(TID/TS): " .. frame_info, " Channel: " .. frame_channel)
  pkt.cols.info:append(", Data Length: " .. (buf:len() - 12) .. " bytes]")

  -- create subtree for myproto
  subtree = root:add(p_myproto, buf(0))
  subtree:append_text(" (" .. buf:len() .. " bytes, " .. frame_type .. " CH" .. frame_channel .. ")")
  
  if pp.enable_frame_timestamp then
	subtree:add(f_frameid8, buf(0,1))--:append_text(" [frame id]")
	subtree:add(f_timestamp, buf(1,3))--:append_text(" [frame id]")
  else
	subtree:add(f_frameid, buf(0,4))--:append_text(" [frame id]")
  end
  
  -- subtree for "frame header"
	h0_tree = subtree:add(p_srsframe, buf(4,8))
	h0_tree: append_text(" [Type: " .. frame_type .. ", Channel: " .. frame_channel .. "]")
		h0_tree: add(ff_type, buf(4, 3))
		h0_tree: add(ff_chan, buf(7, 1))
		h0_tree: add(ff_info, buf(8, 4)): append_text(" [reserved]")
  -- subtree for "frame data"
	local framedata_length = (buf:len() - 12)
	fdtree = subtree:add(p_srsfdata, buf(12))
	fdtree:append_text(" [" .. framedata_length .. " bytes]")
	  if frame_type == "APZ" then
		-- APZ header
		apztree = fdtree:add(p_srsapzheader, buf(12, 8))
			apztree: add(fapz.apvid, buf(12,1))
			apztree: add(fapz.nchan, buf(13,1))
			apztree: add(fapz.nsamp, buf(14,1))
			apztree: add(fapz.zserr, buf(15,1))
			apztree: add(fapz.flags, buf(16,2))
			apztree: add(fapz.zstype, buf(16,2))
			
			apztree: add(fapz.reserved, buf(18,2))
			
		-- fill channel data fields
		local apz_nchan = buf(13,1):uint()
		apzdatatree = fdtree:add(buf(20), "APZ (Zero-suppression APV) Data")
		if apz_nchan > 0 then
			local apz_nsamp = buf(14,1):uint()
			local apz_flags = buf(16,2):uint()
			local apz_zstype = 0x01 and apz_flags
			local offset = 20
			for i=0,apz_nchan - 1,1 do
				local apzdtree = apzdatatree:add(p_srsapzchdata, buf(offset, apz_nsamp*2 + 2))
				local chan_id = buf(offset + 1,1):uint()
				apzdtree:append_text(" [Channel " .. chan_id .. "]")
					apzdtree: add(fapzd.chan_info, buf(offset,1))
					apzdtree: add(fapzd.chan_id, buf(offset + 1,1))
					if apz_zstype == 1 then
						apzdtree: add(fapzd.chan_peak, buf(offset + 2,2))
						apzdtree: add(fapzd.chan_time, buf(offset + 4,2))
					else
						apzdtree: add(fapzd.chan_data, buf(offset + 2,apz_nsamp*2)): append_text(" (" .. apz_nsamp .. " samples)")
						if pp.apz_decode == true then
							local decoded_data = apzdtree: add(buf(offset + 2,apz_nsamp*2), "CHAN_DATA (decoded): ")
							for j=0,apz_nsamp-1,1 do
								local tmp = buf(offset + 2 + 2*j,2):int()
								decoded_data: append_text(tmp)
								if j < apz_nsamp-1 then decoded_data: append_text(", ") end
							end
							decoded_data: append_text(" (" .. apz_nsamp .. " samples)")
						end
					end
				offset = offset + apz_nsamp*2 + 2
			end	
		else
			apzdatatree:append_text(" (empty)")
		end
		--subtree:add(f_data, buf(20)):append_text(" [" .. (buf:len() - 20) .. " bytes]")
	  else
		-- Raw data
		fdtree:add(ffdata.raw, buf(12)):append_text(" (" .. framedata_length/2 .. " samples)")
		if pp.raw_decode then
			local maxs = framedata_length/2
			if framedata_length/2 > pp.raw_decode_limit then maxs = pp.raw_decode_limit end
			
			rawdectree = fdtree:add(buf(12), "Raw Data (decoded):")
			for k=0,maxs,1 do
				local tmp0 = buf(12 + 2*k,1):uint()
				local tmp1 = buf(12 + 2*k + 1,1):uint()
				local sample = tmp0 + tmp1*256
				local samplefield = rawdectree:add(buf(12 + 2*k,2), "Sample ")
				samplefield:append_text(k .. ": \t" .. sample)
				if pp.apv_decode then
					if sample < pp.apv_lowthr then samplefield:append_text( " \t(" .. pp.apv_lowlabel .. ")") end
					if sample > pp.apv_highthr then samplefield:append_text( " \t(" .. pp.apv_highlabel .. ")") end
				end
			end 
		end
	  end

  -- description of payload
  -- add debug info if debug field is not nil
  if f_debug then
    -- write debug values
    subtree:add(f_debug, buf:len())
  end
end

-- Initialization routine
function p_myproto.init()
end

-- register a chained dissector for port 6006
--local udp_dissector_table = DissectorTable.get("udp.port")
--dissector = udp_dissector_table:get_dissector(6006)
  -- you can call dissector from function p_myproto.dissector above
  -- so that the previous dissector gets called
udp_dissector_table:add(6006, p_myproto)

-- Copyright (C) 2016, 2017, 2018 European Spallation Source ERIC
-- Wireshark plugin for dissecting VMM3/SRS readout data

-- helper variable and functions


local t0=0
local fc0=0
local firstMarker = 0
local hit_id = 0


function i64_ax(h,l)
 local o = {}; o.l = l; o.h = h; return o;
end -- +assign 64-bit v.as 2 regs

function i64u(x)
 return ( ( (bit.rshift(x,1) * 2) + bit.band(x,1) ) % (0xFFFFFFFF+1));
end -- keeps [1+0..0xFFFFFFFFF]


function i64_rshift(a,n)
 local o = {};
 if(n==0) then
   o.l=a.l; o.h=a.h;
 else
   if(n<32) then
     o.l= bit.rshift(a.l, n)+i64u( bit.lshift(a.h, (32-n))); o.h=bit.rshift(a.h, n);
   else
     o.l=bit.rshift(a.h, (n-32)); o.h=0;
   end
  end
  return o;
end

function i64_toInt(a)
  return (a.l + (a.h * (0xFFFFFFFF+1)));
end -- value=2^53 or even less, so better use a.l value

function i64_toString(a)
  local s1=string.format("%x",a.l);
  local s2=string.format("%x",a.h);
  return "0x"..string.upper(s2)..string.upper(s1);
end


function gray2bin32(ival)
  ival = bit.bxor(ival, bit.rshift(ival, 16))
  ival = bit.bxor(ival, bit.rshift(ival,  8))
  ival = bit.bxor(ival, bit.rshift(ival,  4))
  ival = bit.bxor(ival, bit.rshift(ival,  2))
  ival = bit.bxor(ival, bit.rshift(ival,  1))
  return ival
end



-- -----------------------------------------------------------------------------------------------
-- the protocol dissector
-- -----------------------------------------------------------------------------------------------
srsvmm_proto = Proto("srssampa","SRSSAMPA Protocol")

function srsvmm_proto.dissector(buffer,pinfo,tree)
	pinfo.cols.protocol = "SRSSAMPA"
	local data_length_byte = 8
	local protolen = buffer():len()
	local srshdr = tree:add(srsvmm_proto,buffer(),"SRS Header")
	local fc = buffer(0,4):uint()
    local last_timestamp1 = 0
    local timestamp1 = 0
    local last_timestamp2 = 0
    local timestamp2 = 0
	if (fc0 == 0) and (fc ~= 0xfafafafa) then
		fc0 = fc
	end

	if fc == 0xfafafafa then
		srshdr:add("Frame Counter: 0xfafafafa (End of Frame)")
		pinfo.cols.info = "End of Frame"
	else
		local dataid = buffer(4,3):uint()
		local time = buffer(8,4):uint()
		if (t0 == 0) then
			t0 = time
		end

		srshdr:add(buffer(0,4),"Frame Counter: " .. fc .. " (" .. (fc-fc0) .. ")")
		if dataid == 0x564d33 then -- VM3 --0x534150 then -- SAP
			local fecid = bit.rshift(buffer(7,1):uint(), 4)
			local overflow = buffer(12,4):uint()
			srshdr:add(buffer(1,1),"Data Id: SAMPA Data")
			srshdr:add(buffer(1,1),"FEC ID: " .. fecid)
			srshdr:add(buffer(1,1),"UDP Timestamp: " .. time .. " (" .. (time - t0) .. ")")
			srshdr:add(buffer(1,1),"Offset overflow last frame: " .. overflow)



			if protolen >= 16 then
				local hits = (protolen-16)/data_length_byte
				--local hit_id = 0
				local marker_id = 0
				for i=1,hits do
		   
					--local d1 = buffer(16 + (i-1)*data_length_byte, 4)
					--local d1 = buffer(0 + (i-1)*data_length_byte, 1)
					--#local d1 = buffer(16 + (i-1)*data_length_byte, 1)
					
					--local d2 = buffer(20 + (i-1)*data_length_byte, 1)
					--local d3 = buffer(18 + (i-1)*data_length_byte, 1)
					--local d4 = buffer(8 + (i-1)*data_length_byte, 1)
					--local d5 = buffer(4 + (i-1)*data_length_byte, 1)
					--local d6 = buffer(0 + (i-1)*data_length_byte, 1)
					
					
					local d1 = buffer(16 + (i-1)*data_length_byte, 4)
					local d2 = buffer(20 + (i-1)*data_length_byte, 4) --64bits
					
					--local queue1 = assert( io.open( "C:/queues/queue1.txt", "a+" ) )
					--local queue2 = assert( io.open( "C:/queues/queue2.txt", "a+" ) )
					--local queue3 = assert( io.open( "C:/queues/queue3.txt", "a+" ) )
					--local queue4 = assert( io.open( "C:/queues/queue4.txt", "a+" ) )
					--local queue5 = assert( io.open( "C:/queues/queue5.txt", "a+" ) )
					--local queue6 = assert( io.open( "C:/queues/queue6.txt", "a+" ) )
					--local queue7 = assert( io.open( "C:/queues/queue7.txt", "a+" ) )
					--local queue8 = assert( io.open( "C:/queues/queue8.txt", "a+" ) )
					--local queue9 = assert( io.open( "C:/queues/queue9.txt", "a+" ) )
					-- local queue10 = assert( io.open( "C:/queues/queue10.txt", "a+" ) )
					-- local queue11 = assert( io.open( "C:/queues/queue11.txt", "a+" ) )
					-- local queue12 = assert( io.open( "C:/queues/queue12.txt", "a+" ) )
					-- local queue13 = assert( io.open( "C:/queues/queue13.txt", "a+" ) )
					-- local queue14 = assert( io.open( "C:/queues/queue14.txt", "a+" ) )
					-- local queue15 = assert( io.open( "C:/queues/queue15.txt", "a+" ) )
					-- local queue16 = assert( io.open( "C:/queues/queue16.txt", "a+" ) )

					-- local d3 = buffer(24 + (i-1)*data_length_byte, 4)
					-- local d4 = buffer(28 + (i-1)*data_length_byte, 4) --128bits
					-- local d5 = buffer(32 + (i-1)*data_length_byte, 4)
					-- local d6 = buffer(36 + (i-1)*data_length_byte, 4) --192bits
					-- local d7 = buffer(40 + (i-1)*data_length_byte, 4)
					-- local d8 = buffer(44 + (i-1)*data_length_byte, 4) --256bits

					-- data marker
					--local flag = bit.band(bit.rshift(d2:uint(), 15), 0x01) 
					
			--		if flag == 0 then
					-- marker
						--data 2 (16 bit):
						-- 	flag: 0: 1 bit
						-- 	vmmid: 1-5 : 5 bit
						--	timestamp: 6-15: 10 bit

						--data 1 (32 bit):
						--	timestamp: 0-31: 32 bit
			--			last_timestamp1 = timestamp1
			--			last_timestamp2 = timestamp2
			--			timestamp1 = d1:uint() 
			--			timestamp2 = bit.lshift(d2:uint(), 22) 
			--			local temp = i64_ax(timestamp1,timestamp2)
						
			--			local timestamp = i64_rshift(temp,22)
			--			if firstMarker == 0 then
			--				firstMarker = i64_toInt(timestamp)
			--			end
			--			marker_id = marker_id + 1
			--			local vmmid =  bit.band(bit.rshift(d2:uint(), 10), 0x1F) 
						
			--			local hit = srshdr:add(buffer(16 + (i-1)*data_length_byte, data_length_byte),
			--				string.format("Marker: %3d, SRS timestamp: %d, vmmid: %d",
			--				marker_id, i64_toInt(timestamp), vmmid))

			--			local d1handle = hit:add(d1, "Data1 " .. d1)
			--			d1handle:add(d1, "timestamp: " .. i64_toString(timestamp))
			--			
			--			local d2handle = hit:add(d2, "Data2 " .. d2)
			--			d2handle:add(d2, "flag: " .. flag)
			--			d2handle:add(d2, "vmmid: " .. vmmid)
						
			--		else
					-- hit
						hit_id = hit_id + 1
						--data 2 (16 bit):
						--	flag: 0
						-- 	overThreshold: 1
						-- 	chno: 2-7 : 6 bit
						-- 	tdc: 8-15: 8 bit

						--data 1 (32 bit):
						-- 	offset: 0-4: 5 bit
						-- 	vmmid: 5-9: 5 bit
						-- 	adc: 10-19: 10 bit
						-- 	bcid: 20-31: 12 bit
									
						
						--local othr = bit.band(bit.rshift(d2:uint(), 14), 0x01) 
						--local chno = bit.band(bit.rshift(d2:uint(), 8), 0x3f) 
						--local tdc  = bit.band(d2:uint(), 0xff) 
						--local queuevalue  = bit.band(d2:uint(), 0xffffffff) 
						--local queuevalue  = bit.band(bit.rshift(d2:uint(), 0), 0xffffff)

					
						--local offset = bit.band(bit.rshift(d1:uint(), 27), 0x1f) 
						--local vmmid = bit.band(bit.rshift(d1:uint(), 22), 0x1f) 
						--local adc   = bit.band(bit.rshift(d1:uint(), 12), 0x03FF) 
						--local gbcid   = bit.band(d1:uint(), 0x0FFF) 
						--local queue   = bit.band(bit.rshift(d1:uint(), 8), 0xff)
						
						-- HEADER + 1st Payload
						-- Bit 63-62 = "11"
						-- Bit 61-52 = 1st Payload
						-- Bit 51-50 = "11"
						-- Bit 49 = Payload Parity
						-- Bit 48-29 = BX Counter
						-- Bit 28-24 = CH Addr
						-- Bit 23-20 = H Addr
						-- Bit 19-10 = Num Word
						-- Bit 09-07 = PKT
						-- Bit 06 = Header Parity
						-- Bit 05-00 = Hamming
						--
						-- Next Payload
						-- Bit 63-62 = "01"
						-- Bit 61-52 = 7th Payload
						-- Bit 51-42 = 6th Payload
						-- Bit 41-32 = 5th Payload
						-- Bit 31-30 = "01"
						-- Bit 29-20 = 4th Payload
						-- Bit 19-10 = 3th Payload
						-- Bit 09-00 = 2nd Payload
						--
						-- local h1   = bit.band(bit.rshift(d1:uint(), 24), 0xff)
						-- local h2   = bit.band(bit.rshift(d1:uint(), 16), 0xff)
						-- local h3   = bit.band(bit.rshift(d1:uint(),  8), 0xff)
						-- local h4   = bit.band(bit.rshift(d1:uint(),  0), 0xff) --32bits
						-- local h5   = bit.band(bit.rshift(d2:uint(), 24), 0xff)
						-- local h6   = bit.band(bit.rshift(d2:uint(), 16), 0xff)
						-- local h7   = bit.band(bit.rshift(d2:uint(),  8), 0xff)
						-- local h8   = bit.band(bit.rshift(d2:uint(),  0), 0xff) --64bits
				
						

						-- Bit 31-30 = "11"
						-- Bit 29-20 = 4th Payload
						-- Bit 19-10 = 3th Payload
						-- Bit 09-00 = 2nd Payload
						local h1   = bit.band(bit.rshift(d1:uint(), 30), 0x003)
						local h9   = bit.band(bit.rshift(d1:uint(), 26), 0x00f)
						local h2   = bit.band(bit.rshift(d1:uint(), 20), 0x03f)
						local h3   = bit.band(bit.rshift(d1:uint(), 10), 0x3ff)
						local h4   = bit.band(bit.rshift(d1:uint(),  0), 0x3ff) --32bits
						
						-- Bit 63-62 = "01"
						-- Bit 61-52 = 7th Payload
						-- Bit 51-42 = 6th Payload
						-- Bit 41-32 = 5th Payload
						
						--local h5   = bit.band(bit.rshift(d2:uint(), 31), 0x001)
						local h5   = bit.band(bit.rshift(d2:uint(), 31), 0x001) -- ID
						local h6   = bit.band(bit.rshift(d2:uint(), 20), 0x3ff)
						local h7   = bit.band(bit.rshift(d2:uint(), 10), 0x3ff)
						local h8   = bit.band(bit.rshift(d2:uint(),  0), 0x3ff) --64bits
						
						
						
						local Payload_Par	= bit.band(bit.rshift(d1:uint(), 17), 0x001)	-- Bit 49 = Payload Parity									
						local BX_Counter    = bit.band(bit.rshift(d1:uint(), 0), 0x1FFFF)	-- Bit 48-29 = BX Counter	29->31->d2 & 0-17 ->d1
						local BX_Coun	= bit.band(bit.rshift(d2:uint(), 29), 0x0F)	    -- Bit 29-31 = BX Counter0										
						
						local CH_Addr	    = bit.band(bit.rshift(d2:uint(), 24), 0x01F)	-- Bit 28-24 = CH Addr										
						local H_Addr	    = bit.band(bit.rshift(d2:uint(), 20), 0x00F)	-- Bit 23-20 = H Addr										
						local Num_Word   	= bit.band(bit.rshift(d2:uint(), 10), 0x3FF)	-- Bit 19-10 = Num Word										
						local PKT		    = bit.band(bit.rshift(d2:uint(), 7),  0x007)	-- Bit 09-07 = PKT											
						local Header_Par	= bit.band(bit.rshift(d2:uint(), 6),  0x001)	-- Bit 06 = Header Parity								 	
						local Hamming   	= bit.band(bit.rshift(d2:uint(), 0),  0x03F)	-- Bit 05-00 = Hamming
						
						local Payloa32a   	= bit.band(bit.rshift(d1:uint(), 24),  0xFF)	-- Bit 31-23 = a
						local Payloa32b   	= bit.band(bit.rshift(d1:uint(), 16),  0xFF)	-- Bit 23-16 = b
						local Payloa32c   	= bit.band(bit.rshift(d1:uint(), 8 ),  0xFF)	-- Bit 15-8 = c
						local Payloa32d   	= bit.band(bit.rshift(d1:uint(), 0 ),  0xFF)	-- Bit 7-00 = d
						
						local Payloa32e   	= bit.band(bit.rshift(d2:uint(), 24),  0xFF)	-- Bit 31-23 = a
						local Payloa32f   	= bit.band(bit.rshift(d2:uint(), 16),  0xFF)	-- Bit 23-16 = b
						local Payloa32g   	= bit.band(bit.rshift(d2:uint(), 8 ),  0xFF)	-- Bit 15-8 = c
						local Payloa32h   	= bit.band(bit.rshift(d2:uint(), 0 ),  0xFF)	-- Bit 7-00 = d

						
						
						-- local h9    = bit.band(bit.rshift(d3:uint(), 30), 0x003)
						-- local h10   = bit.band(bit.rshift(d3:uint(), 20), 0x3ff)
						-- local h11   = bit.band(bit.rshift(d3:uint(), 10), 0x3ff)
						-- local h12   = bit.band(bit.rshift(d3:uint(),  0), 0x3ff) --96bits
						
						-- local h13   = bit.band(bit.rshift(d4:uint(), 30), 0x003)
						-- local h14   = bit.band(bit.rshift(d4:uint(), 20), 0x3ff)
						-- local h15   = bit.band(bit.rshift(d4:uint(), 10), 0x3ff)
						-- local h16   = bit.band(bit.rshift(d4:uint(),  0), 0x3ff) --128bits
						
						-- local h17   = bit.band(bit.rshift(d5:uint(), 30), 0x003)
						-- local h18   = bit.band(bit.rshift(d5:uint(), 20), 0x3ff)
						-- local h19   = bit.band(bit.rshift(d5:uint(), 10), 0x3ff)
						-- local h20   = bit.band(bit.rshift(d5:uint(),  0), 0x3ff) --160bits
						
						-- local h21   = bit.band(bit.rshift(d6:uint(), 30), 0x003)
						-- local h22   = bit.band(bit.rshift(d6:uint(), 20), 0x3ff)
						-- local h23   = bit.band(bit.rshift(d6:uint(), 10), 0x3ff)
						-- local h24   = bit.band(bit.rshift(d6:uint(),  0), 0x3ff) --192bits
						
						-- local h25   = bit.band(bit.rshift(d7:uint(), 30), 0x003)
						-- local h26   = bit.band(bit.rshift(d7:uint(), 20), 0x3ff)
						-- local h27   = bit.band(bit.rshift(d7:uint(), 10), 0x3ff)
						-- local h28   = bit.band(bit.rshift(d7:uint(),  0), 0x3ff) --224bits
						
						-- local h29   = bit.band(bit.rshift(d8:uint(), 30), 0x003)
						-- local h30   = bit.band(bit.rshift(d8:uint(), 20), 0x3ff)
						-- local h31   = bit.band(bit.rshift(d8:uint(), 10), 0x3ff)
						-- local h32   = bit.band(bit.rshift(d8:uint(),  0), 0x3ff)
						

						--local bcid  = gray2bin32(gbcid)
					
					
					

						--local hit = srshdr:add(buffer(16 + (i-1)*data_length_byte, data_length_byte),
						--	string.format("Hit: %3d, offset: %d, vmmID: %2d, ch: %2d, bcid: %4d, tdc: %4d, adc: %4d, over thr: %d",
						--	hit_id, offset, vmmid, chno, bcid, tdc, adc, othr))
						-- local hit = srshdr:add(buffer(16 + (i-1)*data_length_byte, data_length_byte),
							-- string.format("Hit: %3d, ID: %2d %4d %4d %4d ID: %2d %4d %4d %4d ID: %2d %4d %4d %4d ID: %2d %4d %4d %4d ID: %2d %4d %4d %4d ID: %2d %4d %4d %4d  ID: %2d %4d %4d %4d ID: %2d %4d %4d %4d",
							-- hit_id, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20, h21, h22, h23, h24, h25, h26, h27, h28, h29, h30, h31, h32))

	
						--local hit = srshdr:add(buffer(16 + (i-1)*data_length_byte, data_length_byte),
						--	string.format("Hit: %3d, PK: %2x QUEUE: %4d -> %4d %4d FULL: %2x %4d %4d %4d <-",
						--	hit_id, h1, h2, h3, h4, h5, h6, h7, h8))
						if h1 == 0x001 then
							local hit = srshdr:add(buffer(16 + (i-1)*data_length_byte, data_length_byte),
								string.format("Hit	BX_Counter:		%3d	%3d%3d			QUEUE:	%2d	PK:	%x	->	%4d	%4d	%4d	%4d	%4d	<-	FULL:	%2x		Payload_Parity	%d	BX_Counter:	%d%d	CH_Addr:	%d	SAMPA_Addr:	%d	Num_Word:	%d	PKT:	%d	Header	Parity:	%d	Hamming:	%d",
								hit_id, BX_Counter, BX_Coun, h2, h1, h8, h7, h6, h4, h3, h5, Payload_Par, BX_Counter,BX_Coun, CH_Addr, H_Addr, Num_Word, PKT, Header_Par, Hamming   ))

								local d1handle = hit:add(d1,""..d1,d2,""..d2)
								d1handle:add(d1, "Payload Parity: " .. Payload_Par)
								d1handle:add(d1, "BX Counter: " .. BX_Counter)
								d1handle:add(d2, "CH Addr: " .. CH_Addr)
								d1handle:add(d2, "SAMPA Addr: " .. H_Addr)
								d1handle:add(d2, "Num Word: " .. Num_Word)
								d1handle:add(d2, "PKT: " .. PKT)
								d1handle:add(d2, "Header Parity: " .. Header_Par)
								d1handle:add(d2, "Hamming: " .. Hamming)
						else
							local hit = srshdr:add(buffer(16 + (i-1)*data_length_byte, data_length_byte),
								--string.format("Hit:	%3d,	QUEUE:	%2d	PK:	%x	->	%4d	%4d	%4d	%4d	%4d	<-	FULL:	%2x",
								--hit_id, h2, h1, h8, h7, h6, h4, h3, h5 ))
								string.format("							QUEUE:	%2d	PK:	%x	->	%4d	%4d	%4d	%4d	%4d	<-	FULL:	%2x		LINK %d",
								h2, h1, h8, h7, h6, h4, h3, h5, h9 ))
						end
						
						
						
							--if h2 == 0x001 then
							--local hit = srshdr:add(buffer(16 + (i-1)*data_length_byte, data_length_byte),
							--	queue1:write( string.format("	%4d	%4d	%4d	%4d	%4d", h8, h7, h6, h4, h3 )))
								--if h1 == 0x001 then
									--queue1:write( "\n\n                #################### NEW PACKET ################### \n\n")  
								--end 
								--queue1:write( string.format("	%4d	%4d	%4d	%4d	%4d", h8, h7, h6, h4, h3 )) 
							--	queue1:write( "\n" )
							--end
							-- if h2 == 0x002 then
								-- if h1 == 0x001 then
									-- queue2:write( "\n\n                #################### NEW PACKET ################### \n\n")  
								-- end 
								-- queue2:write( string.format("Hit:	%3d,	QUEUE:	%2d	PK:	%x	->	%4d	%4d	%4d	%4d	%4d	<-	FULL:	%2x", hit_id, h2, h1, h8, h7, h6, h4, h3, h5) ) 
								-- queue1:write( "\n" )
							-- end

							-- if h2 == 0x001 then
								-- if h1 == 0x001 then
									-- queue1:write( string.format("\nQUEUE:	%2d	PK:	%x           #################### NEW PACKET ###################\n", h2, h1) )  
									-- queue1:write( "\n" )						
								-- end 
								-- queue1:write( string.format("%d,%d,%d,%d,%d\n", h8, h7, h6, h4, h3) ) 
							-- end

							-- if h2 == 0x002 then
								-- if h1 == 0x001 then
									-- queue2:write( string.format("\nQUEUE:	%2d	PK:	%x           #################### NEW PACKET ###################\n", h2, h1) )  
									-- queue2:write( "\n" )						
								-- end 
								-- queue2:write( string.format("%d,%d,%d,%d,%d\n", h8, h7, h6, h4, h3) ) 
							-- end

							-- if h2 == 0x003 then
								-- if h1 == 0x001 then
									-- queue3:write( string.format("\nQUEUE:	%2d	PK:	%x           #################### NEW PACKET ###################\n", h2, h1) )  
									-- queue3:write( "\n" )						
								-- end 
								-- queue3:write( string.format("%d,%d,%d,%d,%d\n", h8, h7, h6, h4, h3) ) 
							-- end

							-- if h2 == 0x004 then
								-- if h1 == 0x001 then
									-- queue4:write( string.format("\nQUEUE:	%2d	PK:	%x           #################### NEW PACKET ###################\n", h2, h1) )  
									-- queue4:write( "\n" )						
								-- end 
								-- queue4:write( string.format("%d,%d,%d,%d,%d\n", h8, h7, h6, h4, h3) ) 
							-- end

							-- if h2 == 0x005 then
								-- if h1 == 0x001 then
									-- queue5:write( string.format("\nQUEUE:	%2d	PK:	%x           #################### NEW PACKET ###################\n", h2, h1) )  
									-- queue5:write( "\n" )						
								-- end 
								-- queue5:write( string.format("%d,%d,%d,%d,%d\n", h8, h7, h6, h4, h3) ) 
							-- end

							-- if h2 == 0x006 then
								-- if h1 == 0x001 then
									-- queue6:write( string.format("\nQUEUE:	%2d	PK:	%x           #################### NEW PACKET ###################\n", h2, h1) )  
									-- queue6:write( "\n" )						
								-- end 
								-- queue6:write( string.format("%d,%d,%d,%d,%d\n", h8, h7, h6, h4, h3) ) 
							-- end

							--if h2 == 0x007 then
								--if h1 == 0x001 then
								--	queue7:write( string.format("\nQUEUE:	%2d	PK:	%x           #################### NEW PACKET ###################\n", h2, h1) )  
								--	queue7:write( string.format(" Payload %4x %4x %4x %4x\n",Payloa32a ,Payloa32b, Payloa32c, Payloa32d ) ) 
								--	queue7:write( string.format(" Payload Parity	%d	BX Counter:	%d	CH Addr:	%d	H Addr:	%d	Num Word:	%d	PKT:	%d	Header Parity:	%d	Hamming:	%d\n", Payload_Par, BX_Counter, CH_Addr, H_Addr, Num_Word, PKT, Header_Par, Hamming ) ) 
								--	queue7:write( "\n" )						
								--end 
								--queue7:write( string.format("%d,%d,%d,%d,%d\n", h8, h7, h6, h4, h3) ) 
							--end

							-- -- -- -- if h2 == 0x008 then
								-- -- -- -- if h1 == 0x001 then
								-- -- -- -- --	queue8:write( string.format("\n \n QUEUE:	%2d	PK:	%x           #################### NEW PACKET ###################\n", h2, h1) )  
								-- -- -- -- --	queue8:write( string.format(" Payload %x %x %x %x %x %x %x %x\n",Payloa32a ,Payloa32b, Payloa32c, Payloa32d, Payloa32e, Payloa32f, Payloa32g, Payloa32h ) ) 
								-- -- -- -- --	queue8:write( string.format(" Payload Parity	%u	BX Counter:	%u	CH Addr:	%u	H Addr:	%u	Num Word:	%u	PKT:	%u	Header Parity:	%u	Hamming:	%u\n", Payload_Par, BX_Counter, CH_Addr, H_Addr, Num_Word, PKT, Header_Par, Hamming ) ) 
								-- -- -- -- queue8:write( string.format("	CH%u	", CH_Addr ) ) 
								-- -- -- -- --	queue8:write( "\n" )						
								-- -- -- -- end 
								-- -- -- -- queue8:write( string.format("%d	%d	%d	%d	%d	", h8, h7, h6, h4, h3) ) 
							-- -- -- -- end

							-- if h2 == 0x009 then
								-- if h1 == 0x001 then
									-- queue9:write( string.format("\n \n QUEUE:	%2d	PK:	%x           #################### NEW PACKET ###################\n", h2, h1) )  
									-- queue9:write( "\n" )						
								-- end 
								-- queue9:write( string.format(",%d,%d,%d,%d,%d", h8, h7, h6, h4, h3,",") ) 
							-- end

							-- if h2 == 0x010 then
								-- if h1 == 0x001 then
									-- queue10:write( string.format("\nQUEUE:	%2d	PK:	%x           #################### NEW PACKET ###################\n", h2, h1) )  
									-- queue10:write( "\n" )						
								-- end 
								-- queue10:write( string.format("%d,%d,%d,%d,%d\n", h8, h7, h6, h4, h3) ) 
							-- end

							-- if h2 == 0x011 then
								-- if h1 == 0x001 then
									-- queue11:write( string.format("\nQUEUE:	%2d	PK:	%x           #################### NEW PACKET ###################\n", h2, h1) )  
									-- queue11:write( "\n" )						
								-- end 
								-- queue11:write( string.format("%d,%d,%d,%d,%d\n", h8, h7, h6, h4, h3) ) 
							-- end

							-- if h2 == 0x012 then
								-- if h1 == 0x001 then
									-- queue12:write( string.format("\nQUEUE:	%2d	PK:	%x           #################### NEW PACKET ###################\n", h2, h1) )  
									-- queue12:write( "\n" )						
								-- end 
								-- queue12:write( string.format("%d,%d,%d,%d,%d\n", h8, h7, h6, h4, h3) ) 
							-- end

							-- if h2 == 0x013 then
								-- if h1 == 0x001 then
									-- queue13:write( string.format("\nQUEUE:	%2d	PK:	%x           #################### NEW PACKET ###################\n", h2, h1) )  
									-- queue13:write( "\n" )						
								-- end 
								-- queue13:write( string.format("%d,%d,%d,%d,%d\n", h8, h7, h6, h4, h3) ) 
							-- end

							-- if h2 == 0x014 then
								-- if h1 == 0x001 then
									-- queue14:write( string.format("\nQUEUE:	%2d	PK:	%x           #################### NEW PACKET ###################\n", h2, h1) )  
									-- queue14:write( "\n" )						
								-- end 
								-- queue14:write( string.format("%d,%d,%d,%d,%d\n", h8, h7, h6, h4, h3) ) 
							-- end

							-- if h2 == 0x015 then
								-- if h1 == 0x001 then
									-- queue15:write( string.format("\nQUEUE:	%2d	PK:	%x           #################### NEW PACKET ###################\n", h2, h1) )  
									-- queue15:write( "\n" )						
								-- end 
								-- queue15:write( string.format("%d,%d,%d,%d,%d\n", h8, h7, h6, h4, h3) ) 
							-- end

							-- if h2 == 0x016 then
								-- if h1 == 0x001 then
									-- queue16:write( string.format("\nQUEUE:	%2d	PK:	%x           #################### NEW PACKET ###################\n", h2, h1) )  
									-- queue16:write( "\n" )						
								-- end 
								-- queue16:write( string.format("%d,%d,%d,%d,%d\n", h8, h7, h6, h4, h3) ) 
							-- end
							



							--local d1handle = hit:add(d1,""..d1,d2,""..d2)
						--d1handle:add(d1, "h1: " .. h1)
						--d1handle:add(d1, "h2: " .. h2)
						--d1handle:add(d1, "h3: " .. h3)
						--d1handle:add(d1, "h4: " .. h4)
						--d1handle:add(d1, "bcid: " .. bcid)
						
						

						--local d2handle = hit:add(d2, "Data2 " .. d2)
						--d2handle:add(d2, "h5: " .. h5)
						--d2handle:add(d2, "h6: " .. h6)
						--d2handle:add(d2, "chno: " .. chno)
						--d2handle:add(d2, "tdc: " .. tdc)
						
				--	end
				end
				--pinfo.cols.info = string.format("FEC: %d, Hits: %3d", fecid, hit_id, marker_id)
		  		pinfo.cols.info = string.format("Hits: %3d",  hit_id)
		  		
			end
		elseif dataid == 0x564133 then
			srshdr:add(buffer(4,4),"Data Id: No Data")
			pinfo.cols.info = "No Data"
		else
			srshdr:add(buffer(4,4),"Data Id: Unknown data " .. buffer(5,3))
		end
		--queue1:close()
		-- queue2:close()
		-- queue3:close()
		-- queue4:close()
		--queue5:close()
		--queue6:close()
		--queue7:close()
		-----------------queue8:close()
		--queue9:close()
		-- queue10:close()
		-- queue11:close()
		-- queue12:close()
		-- queue13:close()
		-- queue14:close()
		-- queue15:close()
		-- queue16:close()
	end

	
	
end

-- Register the protocol
udp_table = DissectorTable.get("udp.port")
udp_table:add(6006, srsvmm_proto)

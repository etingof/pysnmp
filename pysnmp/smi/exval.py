from pyasn1.type import univ, tag

noSuchObject = univ.Null('').subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x00))
noSuchInstance = univ.Null('').subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x01))
endOfMib = univ.Null('').subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x02))


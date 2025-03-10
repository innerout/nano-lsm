//
//  basic_db.cc
//  YCSB-C
//
//  Created by Jinglei Ren on 12/17/14.
//  Copyright (c) 2014 Jinglei Ren <jinglei@ren.systems>.
//

#include "db_factory.h"

#include "parallax_db_tcp.h"

using ycsbc::YCSBDB;
using ycsbc::DBFactory;

YCSBDB *DBFactory::CreateDB(int num, utils::Properties &props)
{
	return new ParallaxDBTCP(num, props);
}

from src import rules
from src import portfilter as pt

myrule = rules.Rule()
myfilter = pt.PortFilter(myrule)
myfilter.start_sniff()

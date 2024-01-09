package main

import (
	"fmt"
	"log"
	"sync/atomic"
	"time"
)

type Item struct {
	size  uint64
	count uint64
	time  uint64
}

type Stat struct {
	prefix   string
	now      Item
	old      Item
	interval uint64
	stop     chan struct{}
}

func (now *Item) Sub(old Item) {
	now.size -= old.size
	now.count -= old.count
	now.time -= old.time
}

func (now *Item) Div(interval uint64) {
	if now.count != 0 {
		now.time = now.time / now.count
	}
	now.size = now.size / interval
	now.count = now.count / interval
}

func calcUnit(cnt uint64) string {
	if cnt < 1024 {
		return fmt.Sprintf("%d", cnt)
	} else if cnt < 1024*1024 {
		return fmt.Sprintf("%.2fk", float32(cnt)/1024)
	} else if cnt < 1024*1024*1024 {
		return fmt.Sprintf("%.2fM", float32(cnt)/(1024*1024))
	} else {
		return fmt.Sprintf("%.2fG", float32(cnt)/(1024*1024*1024))
	}
}

func calcTime(tm uint64) string {
	if tm < uint64(time.Microsecond) {
		return fmt.Sprintf("%d ns", tm)
	} else if tm < uint64(time.Millisecond) {
		return fmt.Sprintf("%.2f us", float64(tm)/float64(time.Microsecond))
	} else if tm < uint64(time.Second) {
		return fmt.Sprintf("%.2f ms", float64(tm)/float64(time.Millisecond))
	} else {
		return fmt.Sprintf("%.2f s", float64(tm)/float64(time.Second))
	}
}

func (now *Item) Format() string {
	str := fmt.Sprintf("[ time %s , count %s/s , size %s/s ]",
		calcTime(now.time), calcUnit(now.count), calcUnit(now.size))
	return str
}

func (s *Stat) display() {
	timer := time.NewTimer(time.Duration(s.interval) * time.Second)
	for {
		select {
		case <-timer.C:
			{
				now := s.now
				old := s.old

				now.Sub(old)
				now.Div(s.interval)
				str := now.Format()

				log.Printf("[%s] stat: %s\r\n", s.prefix, str)

				s.old = s.now

				timer.Reset(time.Duration(s.interval) * time.Second)
			}
		case <-s.stop:
			{
				timer.Stop()
				return
			}
		}
	}
}

func NewStat(interval int) *Stat {
	s := new(Stat)
	s.interval = uint64(interval)
	s.stop = make(chan struct{}, 1)
	go s.display()
	return s
}

func (s *Stat) Prefix(str string) {
	s.prefix = str
}

func (s *Stat) Add(size int, tm uint64) {
	atomic.AddUint64(&s.now.count, 1)
	atomic.AddUint64(&s.now.size, uint64(size))
	atomic.AddUint64(&s.now.time, tm)
}

func (s *Stat) Delete() {
	s.stop <- struct{}{}
}

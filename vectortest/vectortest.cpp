//
//  vectortest.cpp
//  vectortest
//
//  Created by Simon Heimlicher on 21.10.12.
//  Copyright (c) 2012 Simon Heimlicher. All rights reserved.
//

#include <cstdlib>
#include <ctime>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
using namespace std;

#include <boost/date_time/posix_time/ptime.hpp>
#include <boost/date_time/microsec_time_clock.hpp>
#include <boost/random.hpp>
using namespace boost;
using namespace boost::gregorian; 
using namespace boost::posix_time;

struct Pixel {
    Pixel() {}
    Pixel(unsigned char r, unsigned char g, unsigned char b) : r(r), g(g), b(b) {}
    unsigned char r, g, b;
};

void UseVectorResize() {    
    for (int i = 0; i < 1000; ++i) {
        int dimension = 999;
        
        vector<Pixel> pixels;
        pixels.resize(dimension * dimension);
        
        for (int i = 0; i < dimension * dimension; ++i) {
            pixels[i].r = 255;
            pixels[i].g = 0;
            pixels[i].b = 0;
        }
    }
}

void UseVectorReserve() {
    for (int i = 0; i < 1000; ++i) {
        int dimension = 999;
        
        vector<Pixel> pixels;
        pixels.reserve(dimension * dimension);
        
        for (int i = 0; i < dimension * dimension; ++i) {
            pixels[i].r = 255;
            pixels[i].g = 0;
            pixels[i].b = 0;
        }
    }
}

void UseArray() {
    for (int i = 0; i < 1000; ++i) {
        int dimension = 999;
        
        Pixel * pixels = (Pixel *)malloc(sizeof(Pixel) * dimension * dimension);
        
        for (int i = 0 ; i < dimension * dimension; ++i) {
            pixels[i].r = 255;
            pixels[i].g = 0;
            pixels[i].b = 0;
        }
        free(pixels);
    }
}

// Inspired by http://stackoverflow.com/a/147438/617559
struct boost_mt19937 : std::unary_function<unsigned, unsigned> {
    boost::mt19937 &_state;
    unsigned operator()(unsigned i) {
        boost::uniform_int<> rng(0, i - 1);
        return rng(_state);
    }
    boost_mt19937(boost::mt19937 &state) : _state(state) {}
};

int main(const int argc, const char *argv[]) {
    unsigned n_runs_per_function = 10;
    uint32_t rng_seed = 0;
    typedef void (*void_function_ptr)(void) ;
    unsigned n_functions = 3;
    static void_function_ptr vector_function[] = {
        &UseArray, &UseVectorResize, &UseVectorReserve
    };
    
    string vector_function_str[] = {
        "UseArray",  "UseVectorResize", "UseVectorReserve"
    };

    if (argc > 1) {
        istringstream(argv[1]) >> n_runs_per_function;
        if (argc > 2) {
            istringstream(argv[2]) >> rng_seed;
        }
    }
    unsigned n_runs = n_functions * n_runs_per_function;
    cout << "Perform " << n_runs_per_function << " runs for each of:\n";
    for (unsigned f=0; f < n_functions; ++f) {
        cout << vector_function_str[f] << (f < n_functions-1?", ":"");
    }
    cout << endl;
    
    vector<unsigned> run_order;
    run_order.reserve(n_runs);
    for (unsigned r=0; r < n_runs_per_function; ++r) {
        for (unsigned f=0; f < n_functions; ++f) {
            run_order[r*n_functions + f] = f;
        }
    }
    if (rng_seed == 0) {
        posix_time::ptime t_epoch(date(1970,1,1));
        posix_time::ptime t_now(date_time::microsec_clock<posix_time::ptime>::universal_time());
        posix_time::time_duration d_seed = t_now - t_epoch;
        rng_seed = d_seed.total_milliseconds();
    }
    boost::mt19937 state(rng_seed);        
    boost_mt19937 rand(state);
    std::random_shuffle(run_order.begin(), run_order.end(), rand);

    vector<posix_time::time_duration> duration;
    duration.resize(n_functions);
    
    posix_time::ptime t_begin, t_end;
    for (unsigned r=0; r < n_runs; ++r) {
        unsigned f = run_order[r];
        t_begin = date_time::microsec_clock<posix_time::ptime>::universal_time();
        vector_function[f]();
        t_end = date_time::microsec_clock<posix_time::ptime>::universal_time();
        duration[f] += t_end - t_begin;
    }
    cout << "Duration per run [averaged over " << n_runs_per_function 
        << " runs]: " << endl;
    for (unsigned f=0; f < n_functions; ++f) {
        cout << setw(8) << duration[f].total_milliseconds() / n_runs_per_function / 1000.0
            << " seconds for " << vector_function_str[f] << endl;
    }
    return 0;
}
